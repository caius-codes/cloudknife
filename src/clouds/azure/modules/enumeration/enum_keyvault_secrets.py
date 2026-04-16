# src/clouds/azure/modules/enumeration/enum_keyvault_secrets.py

import json
import subprocess
from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import HttpResponseError

from ...azure_session import AzureSessionManager, AccessTokenCredential
from ...utils.error_handler import handle_azure_error

console = Console()


class _AzCliTokenExpiredError(Exception):
    """Raised by _list_secrets_via_cli when the CLI session token is expired."""
    pass


def enumerate_keyvault_secrets(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate secrets from an Azure Key Vault.

    Uses Azure SDK (azure-keyvault-secrets) with fallback to REST API
    for firewall-restricted vaults.
    """

    # Get vault access token once upfront — avoids a second browser popup if REST fallback is needed
    access_token = session_mgr.get_access_token(scope="vault")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    vault_name = Prompt.ask("[cyan]Key Vault name (vault-name)[/cyan]")
    if not vault_name:
        console.print("[red]Key Vault name is required.[/red]")
        return

    vault_url = f"https://{vault_name}.vault.azure.net"
    console.print(f"[cyan]Enumerating Key Vault secrets from: {vault_url}[/cyan]")

    secrets: List[Dict[str, Any]] = []

    try:
        # Wrap pre-acquired token in a credential so SecretClient can use it directly
        sdk_credential = AccessTokenCredential(token=access_token)
        secret_client = SecretClient(vault_url=vault_url, credential=sdk_credential)

        # List all secret properties
        secret_properties = secret_client.list_properties_of_secrets()

        # Convert to list format
        for prop in secret_properties:
            secrets.append({
                "id": prop.id,
                "name": prop.name,
                "contentType": prop.content_type,
                "attributes": {
                    "enabled": prop.enabled,
                    "created": prop.created_on.isoformat() if prop.created_on else None,
                    "updated": prop.updated_on.isoformat() if prop.updated_on else None,
                    "expires": prop.expires_on.isoformat() if prop.expires_on else None,
                },
            })

    except HttpResponseError as e:
        # Check for ForbiddenByFirewall error (HTTP 403 with specific message)
        if e.status_code == 403 and "ForbiddenByFirewall" in str(e):
            console.print("[yellow]ForbiddenByFirewall error detected.[/yellow]")
            console.print("[yellow]The Key Vault has firewall restrictions.[/yellow]")

            # Ask user if they want to try REST API fallback
            use_api_fallback = Confirm.ask(
                "[cyan]Try REST API fallback with direct bearer token?[/cyan]",
                default=True
            )

            if not use_api_fallback:
                console.print("[dim]Skipping REST API fallback.[/dim]")
                return

            # Try REST API first (same token, no extra popup)
            console.print("[cyan]Attempting REST API fallback...[/cyan]")
            api_url = f"{vault_url}/secrets?api-version=7.4"
            console.print(f"[dim]Calling: {api_url}[/dim]")

            rest_ok = False
            try:
                response = requests.get(
                    api_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30
                )
                response.raise_for_status()

                api_response = response.json()
                secret_values = api_response.get("value", [])

                if not secret_values:
                    console.print("[yellow]No secrets found via REST API.[/yellow]")
                else:
                    for s in secret_values:
                        secrets.append({
                            "id": s.get("id", ""),
                            "name": s.get("id", "").split("/secrets/")[-1].split("/")[0] if "/secrets/" in s.get("id", "") else "",
                            "contentType": s.get("contentType", ""),
                            "attributes": s.get("attributes", {}),
                        })
                    console.print("[green]Successfully retrieved secrets via REST API![/green]")
                    rest_ok = True

            except requests.exceptions.RequestException as api_error:
                console.print(f"[yellow]REST API call failed: {api_error}[/yellow]")

            # If REST didn't work, fall back to Azure CLI
            if not rest_ok:
                console.print("[cyan]Trying Azure CLI fallback (az keyvault secret list)...[/cyan]")
                try:
                    cli_secrets = _list_secrets_via_cli(vault_name)
                except _AzCliTokenExpiredError:
                    console.print("[yellow]Azure CLI session token is expired.[/yellow]")
                    do_login = Confirm.ask(
                        "[cyan]Run 'az login' now to refresh the CLI session?[/cyan]",
                        default=True
                    )
                    if not do_login:
                        return
                    tenant_id = session_mgr.current_session_data.get("tenant_id")
                    az_cmd = ["az", "login"]
                    if tenant_id:
                        az_cmd += ["--tenant", tenant_id]
                    proc = subprocess.run(az_cmd, timeout=120)
                    if proc.returncode != 0:
                        console.print("[red]az login failed.[/red]")
                        return
                    try:
                        cli_secrets = _list_secrets_via_cli(vault_name)
                    except _AzCliTokenExpiredError:
                        console.print("[red]Still expired after az login. Try running 'az logout' then 'az login'.[/red]")
                        return
                if cli_secrets is None:
                    return
                secrets.extend(cli_secrets)
                if not secrets:
                    console.print("[yellow]No secrets found via Azure CLI.[/yellow]")
                    return
                console.print("[green]Successfully retrieved secrets via Azure CLI![/green]")

        else:
            # Different error
            handle_azure_error(e, "enumerating Key Vault secrets", vault_name)
            return

    except Exception as e:
        handle_azure_error(e, "enumerating Key Vault secrets", vault_name)
        return

    if not secrets:
        console.print("[yellow]No secrets found in this Key Vault.[/yellow]")
        return

    # Save in session
    key = f"keyvault_secrets:{vault_name}"
    session_mgr.save_enumeration_data(key, secrets)

    # Display results
    table = Table(
        title=f"Key Vault secrets in: {vault_name} ({len(secrets)} found)",
        show_lines=False,
    )
    table.add_column("Name", style="cyan")
    table.add_column("Content Type", style="magenta")
    table.add_column("Enabled", style="green")
    table.add_column("ID", style="white", overflow="fold", no_wrap=False)

    for s in secrets:
        name = s.get("name", "")
        content_type = s.get("contentType", "")
        attrs = s.get("attributes", {})
        enabled = attrs.get("enabled", True)

        table.add_row(
            name,
            content_type,
            "Yes" if enabled else "No",
            s.get("id", ""),
        )

    console.print(table)
    console.print(f"[dim]Saved as '{key}' in this session's enumeration data.[/dim]")
    console.print(f"[green]Enumerated {len(secrets)} secret(s).[/green]")


def _list_secrets_via_cli(vault_name: str):
    """
    Fallback: enumerate Key Vault secret metadata via Azure CLI.

    Uses `az keyvault secret list --vault-name <name> [--subscription <id>]`.
    Passes --subscription directly to avoid a separate az account set call.
    Returns a list of normalized secret dicts, or None on fatal error.
    """
    cmd = ["az", "keyvault", "secret", "list", "--vault-name", vault_name, "--output", "json"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        console.print("[red]az CLI not found. Install Azure CLI to use this fallback.[/red]")
        return None
    except subprocess.TimeoutExpired:
        console.print("[red]az CLI timed out.[/red]")
        return None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "AADSTS50173" in stderr or "TokensValidFrom" in stderr:
            raise _AzCliTokenExpiredError(stderr)
        console.print(f"[red]az CLI error: {stderr}[/red]")
        return None

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        console.print(f"[red]Failed to parse az CLI output: {e}[/red]")
        return None

    secrets = []
    for s in raw:
        sid = s.get("id", "")
        name = sid.split("/secrets/")[-1].split("/")[0] if "/secrets/" in sid else s.get("name", "")
        attrs = s.get("attributes", {})
        secrets.append({
            "id": sid,
            "name": name,
            "contentType": s.get("contentType", ""),
            "attributes": {
                "enabled": attrs.get("enabled", True),
                "created": attrs.get("created", ""),
                "updated": attrs.get("updated", ""),
                "expires": attrs.get("expires", ""),
            },
        })
    return secrets
