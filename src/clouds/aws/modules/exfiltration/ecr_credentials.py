import base64
from typing import Optional

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def ecr_get_login(
    session_mgr: AWSSessionManager,
    registry_id: Optional[str] = None,
    region: Optional[str] = None,
) -> None:
    """
    Retrieve ECR authorization token (ecr:GetAuthorizationToken).

    Decodes the base64 token to extract username (AWS) and password, then
    prints ready-to-use docker and podman login commands.

    Args:
        registry_id: AWS account ID of the registry (optional — defaults to current account).
        region:      AWS region for the ECR endpoint (optional — defaults to session default).
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    effective_region = region or Prompt.ask(
        "[cyan]Region[/cyan]", default=session_mgr.default_region
    )

    aws_sess = session_mgr.get_boto3_session()
    ecr = aws_sess.client("ecr", region_name=effective_region)

    kwargs = {}
    if registry_id:
        kwargs["registryIds"] = [registry_id]

    console.print(
        f"[bold blue]🔑 Retrieving ECR authorization token [{effective_region}]"
        + (f" for registry {registry_id}" if registry_id else "") + "[/bold blue]"
    )

    try:
        resp = ecr.get_authorization_token(**kwargs)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        console.print(f"[red]Failed to get ECR authorization token: {code}[/red]")
        console.print("[yellow]Ensure ecr:GetAuthorizationToken permission.[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Failed to get ECR authorization token: {str(e)}[/red]")
        return

    auth_data = resp.get("authorizationData", [])
    if not auth_data:
        console.print("[yellow]No authorization data returned.[/yellow]")
        return

    results = []
    for entry in auth_data:
        token_b64 = entry.get("authorizationToken", "")
        proxy_endpoint = entry.get("proxyEndpoint", "")
        expires_at = entry.get("expiresAt")

        try:
            decoded = base64.b64decode(token_b64).decode("utf-8")
            username, _, password = decoded.partition(":")
        except Exception:
            username = "AWS"
            password = token_b64
            decoded = token_b64

        expires_str = str(expires_at) if expires_at else "unknown"
        registry_url = proxy_endpoint.lstrip("https://")

        # Display table
        t = Table(title=f"ECR Credentials — {proxy_endpoint}")
        t.add_column("Field", style="cyan")
        t.add_column("Value")
        t.add_row("Registry", Text(proxy_endpoint))
        t.add_row("Region", effective_region)
        t.add_row("ExpiresAt", expires_str)
        t.add_row("Username", username)
        t.add_row("Password", Text(password[:80] + ("..." if len(password) > 80 else "")))
        console.print(t)

        console.print("[bold yellow]docker login:[/bold yellow]")
        console.print(f"  docker login --username {username} --password {password} {proxy_endpoint}\n")
        console.print("[bold yellow]podman login:[/bold yellow]")
        console.print(f"  echo '{password}' | podman login --username {username} --password-stdin {registry_url}\n")

        results.append({
            "ProxyEndpoint": proxy_endpoint,
            "Region": effective_region,
            "ExpiresAt": expires_str,
            "Username": username,
            "Password": password,
            "AuthorizationToken": token_b64,
        })

    session_mgr.save_enumeration_data("ecr_credentials", results)
    console.print("[green]Credentials saved under 'ecr_credentials' in session data.[/green]")
