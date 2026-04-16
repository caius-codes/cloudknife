from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory
from src.clouds.aws.utils.error_handling import safe_aws_call


console = Console()


def enumerate_secrets(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate AWS Secrets Manager secrets across configured regions.
    Saves results under 'secrets_manager' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="Secrets Manager")
    console.print(
        f"[bold blue]🔍 Enumerating Secrets Manager secrets in regions: {', '.join(regions)}[/bold blue]"
    )

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)
    all_secrets: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            sm = client_factory.get_client("secretsmanager", region)

            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate(MaxResults=100):
                for s in page.get("SecretList", []):
                    # Extract current version ID from VersionIdsToStages
                    version_id = ""
                    version_stages = s.get("VersionIdsToStages", {})
                    for vid, stages in version_stages.items():
                        if "AWSCURRENT" in stages:
                            version_id = vid
                            break

                    all_secrets.append(
                        {
                            "Region": region,
                            "ARN": s.get("ARN", ""),
                            "Name": s.get("Name", ""),
                            "Description": s.get("Description", ""),
                            "VersionId": version_id,
                            "CreatedDate": str(s.get("CreatedDate", ""))[:19],
                            "LastChangedDate": str(s.get("LastChangedDate", ""))[:19]
                            if s.get("LastChangedDate")
                            else "",
                            "KmsKeyId": s.get("KmsKeyId", ""),
                            "RotationEnabled": s.get("RotationEnabled", False),
                        }
                    )
        except Exception as e:
            console.print(f"[red]Secrets enumeration failed in region {region}: {str(e)}[/red]")

    session_mgr.save_enumeration_data("secrets_manager", all_secrets)

    if not all_secrets:
        console.print("[yellow]No secrets found in the selected regions.[/yellow]")
        return

    table = Table(title=f"Secrets Manager - Secrets (total: {len(all_secrets)})")
    table.add_column("Region", style="magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Version ID", style="dim")
    table.add_column("Rotation")
    table.add_column("KMS Key")
    table.add_column("Created")

    for s in all_secrets:
        rotation_flag = "🔁" if s["RotationEnabled"] else "–"
        table.add_row(
            s["Region"],
            s["Name"],
            s["VersionId"] or "–",
            rotation_flag,
            s["KmsKeyId"] or "–",
            s["CreatedDate"],
        )

    console.print(table)
    console.print(
        "[green]Secrets metadata stored under key 'secrets_manager' in session data.[/green]"
    )

    # Ask user if they want to attempt retrieving secret values
    console.print(
        "\n[bold yellow]⚠️  Attempt to retrieve secret values? (requires secretsmanager:GetSecretValue)[/bold yellow]"
    )
    console.print("[dim]Options:[/dim]")
    console.print("[dim]  1. Try all secrets (may reveal resource-scoped permissions)[/dim]")
    console.print("[dim]  2. Try one specific secret[/dim]")
    console.print("[dim]  3. Skip (default)[/dim]")

    choice = Prompt.ask(
        "[cyan]Enter your choice[/cyan]",
        choices=["1", "2", "3"],
        default="3"
    )

    if choice == "1":
        # Try all secrets
        console.print("\n[bold blue]Attempting to retrieve all secret values...[/bold blue]")
        _retrieve_all_secrets(session_mgr, all_secrets, client_factory)
    elif choice == "2":
        # Try one specific secret
        secret_names = [s["Name"] for s in all_secrets]
        console.print(f"\n[cyan]Available secrets:[/cyan]")
        for idx, name in enumerate(secret_names, 1):
            console.print(f"  {idx}. {name}")

        secret_name = Prompt.ask("[cyan]Enter secret name[/cyan]")
        if secret_name in secret_names:
            secret = next(s for s in all_secrets if s["Name"] == secret_name)
            _retrieve_single_secret(session_mgr, secret, client_factory)
        else:
            console.print(f"[yellow]Secret '{secret_name}' not found in enumerated secrets.[/yellow]")
    else:
        console.print("[dim]Skipped secret value retrieval.[/dim]")
        console.print(
            "[dim]Use 'secret_value <Name or ARN>' to retrieve specific secret values later.[/dim]"
        )


def _retrieve_single_secret(
    session_mgr: AWSSessionManager,
    secret: Dict[str, Any],
    client_factory: RegionalClientFactory
) -> None:
    """Retrieve value for a single secret."""
    secret_name = secret["Name"]
    region = secret["Region"]

    console.print(f"\n[bold blue]Retrieving secret: {secret_name} (region: {region})[/bold blue]")

    sm = client_factory.get_client("secretsmanager", region)
    resp, error = safe_aws_call(
        sm.get_secret_value,
        SecretId=secret_name,
        log_error=False,
        default=None
    )

    if error:
        console.print(f"[red]✗ {secret_name}: {error.code} - {error.message[:100]}[/red]")
        return

    if not resp:
        console.print(f"[yellow]✗ {secret_name}: No response[/yellow]")
        return

    # Success - display the secret
    console.print(f"[green bold]✓ {secret_name}: Successfully retrieved![/green bold]")
    if "VersionId" in resp:
        console.print(f"[dim]Version ID: {resp['VersionId']}[/dim]")

    secret_string = resp.get("SecretString")
    secret_binary = resp.get("SecretBinary")

    if secret_string is not None:
        console.print("[bold cyan]SecretString:[/bold cyan]")
        console.print(f"[magenta]{secret_string}[/magenta]")
    elif secret_binary is not None:
        console.print("[bold magenta]SecretBinary (base64-encoded):[/bold magenta]")
        console.print(str(secret_binary), markup=False, emoji=False)
    else:
        console.print("[yellow]No SecretString or SecretBinary found.[/yellow]")


def _retrieve_all_secrets(
    session_mgr: AWSSessionManager,
    secrets: List[Dict[str, Any]],
    client_factory: RegionalClientFactory
) -> None:
    """Attempt to retrieve values for all enumerated secrets."""
    results = {
        "allowed": [],
        "denied": [],
        "error": []
    }

    for idx, secret in enumerate(secrets, 1):
        secret_name = secret["Name"]
        region = secret["Region"]

        console.print(f"[dim]  [{idx}/{len(secrets)}] Testing: {secret_name}[/dim]")

        sm = client_factory.get_client("secretsmanager", region)
        resp, error = safe_aws_call(
            sm.get_secret_value,
            SecretId=secret_name,
            log_error=False,
            default=None
        )

        if error:
            if "AccessDenied" in error.code or "AccessDeniedException" in error.code:
                results["denied"].append({
                    "name": secret_name,
                    "region": region,
                    "error": error.code
                })
            else:
                results["error"].append({
                    "name": secret_name,
                    "region": region,
                    "error": f"{error.code}: {error.message[:80]}"
                })
        elif resp:
            secret_string = resp.get("SecretString", "")
            secret_binary = resp.get("SecretBinary")

            results["allowed"].append({
                "name": secret_name,
                "region": region,
                "value_type": "binary" if secret_binary else "string",
                "value_preview": secret_string[:50] + "..." if len(secret_string) > 50 else secret_string
            })

    # Display summary table
    console.print(f"\n[bold cyan]Secret Value Retrieval Results:[/bold cyan]")
    console.print(f"  [green]✓ Allowed:[/green] {len(results['allowed'])} secret(s)")
    console.print(f"  [red]✗ Denied:[/red] {len(results['denied'])} secret(s)")
    console.print(f"  [yellow]⚠ Errors:[/yellow] {len(results['error'])} secret(s)")

    if results["allowed"]:
        console.print(f"\n[green bold]Secrets with accessible values ({len(results['allowed'])}):[/green bold]")
        value_table = Table()
        value_table.add_column("Secret Name", style="cyan", overflow="fold", no_wrap=False)
        value_table.add_column("Region", style="magenta", overflow="fold", no_wrap=False)
        value_table.add_column("Type", overflow="fold", no_wrap=False)
        value_table.add_column("Value Preview", overflow="fold", no_wrap=False)

        for s in results["allowed"]:
            value_table.add_row(
                s["name"],
                s["region"],
                s["value_type"],
                Text(s.get("value_preview", ""), style="dim")
            )

        console.print(value_table)
        console.print(
            "[dim]Use 'secret_value <Name>' to view full secret values individually.[/dim]"
        )

    if results["denied"]:
        console.print(f"\n[red]Access Denied ({len(results['denied'])}):[/red]")
        for s in results["denied"][:10]:
            console.print(f"  • {s['name']} ({s['region']})")
        if len(results["denied"]) > 10:
            console.print(f"  [dim]... and {len(results['denied']) - 10} more[/dim]")

    if results["error"]:
        console.print(f"\n[yellow]Errors ({len(results['error'])}):[/yellow]")
        for s in results["error"][:5]:
            console.print(f"  • {s['name']}: {s['error']}")
        if len(results["error"]) > 5:
            console.print(f"  [dim]... and {len(results['error']) - 5} more[/dim]")

    # Save results to session
    session_mgr.save_enumeration_data("secrets_value_test_results", results)
