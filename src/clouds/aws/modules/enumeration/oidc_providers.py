"""
OIDC Provider Enumeration Module

Enumerates all OpenID Connect (OIDC) identity providers configured in IAM.
Lists provider details including issuer URLs, thumbprints, client IDs, and tags.

Note: IAM is a global service, so this enumeration is not region-specific.
"""

from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager

console = Console()


def enumerate_oidc_providers(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate all OpenID Connect (OIDC) identity providers in IAM.

    Collects for each provider:
    - ARN
    - Issuer URL
    - Client ID list
    - Thumbprint list
    - Creation date
    - Tags

    IAM is a global service, so this operates on the account level regardless of region.

    Required Permissions:
    - iam:ListOpenIDConnectProviders (required)
    - iam:GetOpenIDConnectProvider (for detailed info)
    - iam:ListOpenIDConnectProviderTags (for tags)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold blue]🔍 Enumerating OIDC identity providers[/bold blue]\n")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    # Step 1: List all OIDC providers
    try:
        console.print("[dim]→ Listing OIDC providers...[/dim]")
        response = iam.list_open_id_connect_providers()
        provider_list = response.get("OpenIDConnectProviderList", [])

        if not provider_list:
            console.print("[yellow]No OIDC identity providers found in this account.[/yellow]")
            return

        console.print(f"[green]✓ Found {len(provider_list)} OIDC provider(s)[/green]\n")

    except Exception as e:
        console.print(f"[red]Failed to list OIDC providers: {str(e)}[/red]")
        console.print("[yellow]Ensure iam:ListOpenIDConnectProviders permission.[/yellow]")
        return

    # Step 2: Get detailed information for each provider
    console.print("[dim]→ Fetching provider details...[/dim]")
    providers: List[Dict[str, Any]] = []

    for provider in provider_list:
        provider_arn = provider["Arn"]

        try:
            # Get provider details
            details = iam.get_open_id_connect_provider(
                OpenIDConnectProviderArn=provider_arn
            )

            # Get tags if available
            tags = []
            try:
                tags_response = iam.list_open_id_connect_provider_tags(
                    OpenIDConnectProviderArn=provider_arn
                )
                tags = tags_response.get("Tags", [])
            except Exception:
                # Tags might not be accessible or not supported
                pass

            provider_info = {
                "Arn": provider_arn,
                "Url": details.get("Url", ""),
                "ClientIDList": details.get("ClientIDList", []),
                "ThumbprintList": details.get("ThumbprintList", []),
                "CreateDate": str(details.get("CreateDate", ""))[:19],
                "Tags": tags,
            }

            providers.append(provider_info)

        except Exception as e:
            console.print(f"[red]  Failed to get details for {provider_arn}: {str(e)[:100]}[/red]")
            # Add minimal info if we can't get details
            providers.append({
                "Arn": provider_arn,
                "Url": "Error fetching details",
                "ClientIDList": [],
                "ThumbprintList": [],
                "CreateDate": "",
                "Tags": [],
            })

    # Save results
    session_mgr.save_enumeration_data("oidc_providers", providers)

    # Display results
    console.print(f"\n[bold]📋 OIDC Providers Summary ({len(providers)} total)[/bold]\n")

    table = Table(title="OpenID Connect Identity Providers")
    table.add_column("Issuer URL", style="cyan", no_wrap=False)
    table.add_column("ARN", style="dim", no_wrap=False, max_width=60)
    table.add_column("Client IDs", style="green")
    table.add_column("Thumbprints", style="yellow", justify="center")
    table.add_column("Created", style="dim")
    table.add_column("Tags", justify="center")

    for provider in providers:
        url = provider["Url"]
        arn = provider["Arn"]
        client_ids = provider["ClientIDList"]
        thumbprints = provider["ThumbprintList"]
        created = provider["CreateDate"]
        tags = provider["Tags"]

        # Format client IDs
        if len(client_ids) == 0:
            client_ids_str = "[dim]none[/dim]"
        elif len(client_ids) == 1:
            client_ids_str = client_ids[0]
        else:
            client_ids_str = f"{len(client_ids)} IDs"

        # Format thumbprints
        thumbprints_str = str(len(thumbprints)) if thumbprints else "[dim]0[/dim]"

        # Format tags
        tags_str = str(len(tags)) if tags else "[dim]0[/dim]"

        table.add_row(
            url,
            arn,
            client_ids_str,
            thumbprints_str,
            created,
            tags_str
        )

    console.print(table)

    # Show detailed info for each provider
    console.print(f"\n[bold]📄 Detailed Provider Information[/bold]\n")

    for idx, provider in enumerate(providers, 1):
        console.print(f"[bold cyan]{idx}. {provider['Url']}[/bold cyan]")
        console.print(f"   [dim]ARN:[/dim] {provider['Arn']}")
        console.print(f"   [dim]Created:[/dim] {provider['CreateDate']}")

        # Client IDs
        client_ids = provider["ClientIDList"]
        if client_ids:
            console.print(f"   [dim]Client IDs ({len(client_ids)}):[/dim]")
            for client_id in client_ids:
                console.print(f"      • {client_id}")
        else:
            console.print(f"   [dim]Client IDs:[/dim] [yellow]none configured[/yellow]")

        # Thumbprints
        thumbprints = provider["ThumbprintList"]
        if thumbprints:
            console.print(f"   [dim]Thumbprints ({len(thumbprints)}):[/dim]")
            for thumbprint in thumbprints:
                console.print(f"      • {thumbprint}")
        else:
            console.print(f"   [dim]Thumbprints:[/dim] [yellow]none configured[/yellow]")

        # Tags
        tags = provider["Tags"]
        if tags:
            console.print(f"   [dim]Tags ({len(tags)}):[/dim]")
            for tag in tags:
                console.print(f"      • {tag['Key']}: {tag['Value']}")
        else:
            console.print(f"   [dim]Tags:[/dim] [dim]none[/dim]")

        console.print()  # Empty line between providers

    # Identify common provider types
    github_providers = [p for p in providers if "github" in p["Url"].lower()]
    google_providers = [p for p in providers if "accounts.google.com" in p["Url"].lower()]

    if github_providers or google_providers:
        console.print("[bold]🔍 Common Providers Detected:[/bold]")
        if github_providers:
            console.print(f"  • GitHub Actions: {len(github_providers)} provider(s)")
        if google_providers:
            console.print(f"  • Google Workspace: {len(google_providers)} provider(s)")
        console.print()

    console.print(
        f"[green]✓ Enumeration complete. Results saved to session data under 'oidc_providers'.[/green]"
    )

    # Hint about related commands
    console.print(
        "\n[dim]💡 Tip: Use 'enumerate_vulnerable_oidc' to check for security issues in GitHub OIDC configurations.[/dim]"
    )
