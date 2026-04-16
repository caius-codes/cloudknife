# src/clouds/azure/utils/graph_helpers.py

import base64
import json
import time
from typing import List, Dict, Any, Optional

import requests
from rich.console import Console

console = Console()


def paginated_graph_request(
    access_token: str,
    url: str,
    limit: Optional[int] = None
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch all pages from a Graph API endpoint that returns paginated results.

    Args:
        access_token: Valid Graph API access token
        url: Full Graph API endpoint URL
        limit: Optional maximum number of items to retrieve

    Returns:
        List of all items from all pages, or None if there was an API error
    """
    all_items = []
    current_url = url
    page_count = 0

    while current_url:
        page_count += 1
        console.print(f"[dim]Fetching page {page_count}...[/dim]")

        try:
            response = requests.get(
                current_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=60
            )

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                console.print(f"[yellow]Rate limited. Waiting {retry_after} seconds...[/yellow]")
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()

            # Extract items (Graph API uses "value" key)
            items = data.get("value", [])
            all_items.extend(items)

            # Check if we've hit the limit
            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                console.print(f"[dim]Reached limit of {limit} items.[/dim]")
                break

            # Check for next page
            current_url = data.get("@odata.nextLink")

            if not current_url:
                console.print(f"[dim]Retrieved {len(all_items)} item(s) total.[/dim]")

        except requests.exceptions.HTTPError as e:
            # Try to extract detailed error message from Graph API response
            error_detail = ""
            try:
                error_data = e.response.json()
                error_msg = error_data.get("error", {}).get("message", "")
                error_code = error_data.get("error", {}).get("code", "")
                if error_msg:
                    error_detail = f": {error_msg}"
                if error_code and error_code not in error_msg:
                    error_detail = f" ({error_code}){error_detail}"
            except:
                pass

            if e.response.status_code == 401:
                console.print(f"[red]Authentication failed: Token expired or invalid{error_detail}[/red]")
                console.print("[yellow]Run 'get_graph_token' or 'login_interactive' to re-authenticate.[/yellow]")
            elif e.response.status_code == 403:
                console.print(f"[red]Permission denied: Insufficient privileges{error_detail}[/red]")
                console.print("[yellow]Required permission may be missing from your token.[/yellow]")
                console.print("[dim]Hint: Run 'bruteforce_graph_permissions' to enumerate your actual permissions.[/dim]")
            elif e.response.status_code == 404:
                console.print(f"[yellow]Resource not found{error_detail}[/yellow]")
                console.print("[dim]This may indicate: (1) No mailbox/resource exists for this user, or (2) Invalid endpoint/ID.[/dim]")
            else:
                console.print(f"[red]HTTP error {e.response.status_code}{error_detail}[/red]")
            return None
        except requests.exceptions.Timeout:
            console.print("[red]Request timed out. Retrying...[/red]")
            time.sleep(5)
            continue
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request failed: {e}[/red]")
            return None
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse JSON response: {e}[/red]")
            return None

    return all_items


def graph_api_call(
    access_token: str,
    method: str,
    url: str,
    data: Optional[Dict] = None
) -> Optional[Dict[str, Any]]:
    """
    Make a single Graph API call with error handling.

    Args:
        access_token: Valid Graph API access token
        method: HTTP method (GET, POST, PATCH, DELETE)
        url: Full Graph API endpoint URL
        data: Optional JSON data for POST/PATCH requests

    Returns:
        Parsed JSON response or None on error
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=60)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=60)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=headers, json=data, timeout=60)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, timeout=60)
            else:
                console.print(f"[red]Unsupported HTTP method: {method}[/red]")
                return None

            # Handle rate limiting with exponential backoff
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                wait_time = min(retry_after, 2 ** retry_count * 5)
                console.print(f"[yellow]Rate limited. Waiting {wait_time} seconds...[/yellow]")
                time.sleep(wait_time)
                retry_count += 1
                continue

            response.raise_for_status()

            # Some endpoints return 204 No Content
            if response.status_code == 204:
                return {}

            return response.json()

        except requests.exceptions.HTTPError as e:
            # Try to extract detailed error message from Graph API response
            error_detail = ""
            error_msg = ""
            try:
                error_data = e.response.json()
                error_msg = error_data.get("error", {}).get("message", "")
                error_code = error_data.get("error", {}).get("code", "")
                if error_msg:
                    error_detail = f": {error_msg}"
                if error_code and error_code not in error_msg:
                    error_detail = f" ({error_code}){error_detail}"
            except:
                pass

            if e.response.status_code == 401:
                console.print(f"[red]Authentication failed: Token expired or invalid{error_detail}[/red]")
                console.print("[yellow]Run 'get_graph_token' or 'login_interactive' to re-authenticate.[/yellow]")
            elif e.response.status_code == 403:
                console.print(f"[red]Permission denied: Insufficient privileges{error_detail}[/red]")
                console.print("[yellow]Required permission may be missing from your token.[/yellow]")
                console.print("[dim]Hint: Run 'bruteforce_graph_permissions' to enumerate your actual permissions.[/dim]")
            elif e.response.status_code == 404:
                console.print(f"[yellow]Resource not found{error_detail}[/yellow]")
                console.print("[dim]This may indicate: (1) No mailbox/resource exists, or (2) Invalid endpoint/ID.[/dim]")
            else:
                console.print(f"[red]HTTP error {e.response.status_code}{error_detail}[/red]")
            return None
        except requests.exceptions.Timeout:
            console.print(f"[yellow]Request timed out. Retry {retry_count + 1}/{max_retries}...[/yellow]")
            retry_count += 1
            time.sleep(2 ** retry_count)
            continue
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request failed: {e}[/red]")
            return None
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse JSON response: {e}[/red]")
            return None

    console.print("[red]Max retries exceeded.[/red]")
    return None


def check_token_scopes(access_token: str, required_scopes: List[str]) -> Dict[str, bool]:
    """
    Decode JWT access token and check if required scopes are present.

    This is a best-effort check - it decodes the token without verification.
    The actual permissions are enforced by the Graph API.

    Args:
        access_token: JWT access token
        required_scopes: List of required scope names (e.g., ["Mail.Read", "User.Read"])

    Returns:
        Dictionary mapping each required scope to True/False (present/missing)
    """
    result = {scope: False for scope in required_scopes}

    try:
        # JWT tokens have 3 parts separated by dots: header.payload.signature
        parts = access_token.split('.')
        if len(parts) != 3:
            console.print("[yellow]Invalid token format. Cannot check scopes.[/yellow]")
            return result

        # Decode the payload (second part)
        payload = parts[1]

        # Add padding if needed (JWT base64 encoding omits padding)
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        # Decode base64
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)

        # Extract scopes - can be in 'scp' (delegated) or 'roles' (application)
        token_scopes = []

        # Delegated permissions (user context)
        if 'scp' in claims:
            # Scopes are space-separated
            token_scopes.extend(claims['scp'].split(' '))

        # Application permissions (app-only context)
        if 'roles' in claims:
            # Roles are a list
            token_scopes.extend(claims['roles'])

        # Check each required scope
        for scope in required_scopes:
            result[scope] = scope in token_scopes

        # Print summary
        missing_scopes = [s for s, present in result.items() if not present]
        if missing_scopes:
            console.print(f"[yellow]Warning: Token may lack required scopes: {', '.join(missing_scopes)}[/yellow]")
            console.print("[dim]The operation may fail or return partial results.[/dim]")
        else:
            console.print(f"[green]Token has all required scopes: {', '.join(required_scopes)}[/green]")

    except Exception as e:
        console.print(f"[yellow]Could not decode token to check scopes: {e}[/yellow]")
        console.print("[dim]Proceeding anyway - the API will enforce permissions.[/dim]")

    return result


def format_file_size(size_bytes: int) -> str:
    """
    Convert bytes to human-readable file size.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def download_file_stream(
    access_token: str,
    download_url: str,
    dest_path: str,
    show_progress: bool = True
) -> bool:
    """
    Download a file from Graph API with streaming to avoid loading into memory.

    Args:
        access_token: Valid Graph API access token
        download_url: URL to download content
        dest_path: Local file path to save to
        show_progress: Whether to show progress bar

    Returns:
        True if successful, False otherwise
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}

        # Stream the response
        response = requests.get(download_url, headers=headers, stream=True, timeout=120)
        response.raise_for_status()

        # Get file size if available
        total_size = int(response.headers.get('content-length', 0))

        if show_progress and total_size > 0:
            from rich.progress import Progress, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn

            with Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Downloading...", total=total_size)

                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
                        if chunk:
                            f.write(chunk)
                            progress.update(task, advance=len(chunk))
        else:
            # No progress bar
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)

        console.print(f"[green]Downloaded to: {dest_path}[/green]")
        return True

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            console.print("[red]Token expired. Please re-authenticate.[/red]")
        elif e.response.status_code == 403:
            console.print("[red]Insufficient permissions to download this file.[/red]")
        elif e.response.status_code == 404:
            console.print("[red]File not found or has been deleted.[/red]")
        else:
            console.print(f"[red]Download failed: HTTP {e.response.status_code}[/red]")
        return False
    except requests.exceptions.Timeout:
        console.print("[red]Download timed out.[/red]")
        return False
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Download failed: {e}[/red]")
        return False
    except IOError as e:
        console.print(f"[red]Failed to write file: {e}[/red]")
        return False
