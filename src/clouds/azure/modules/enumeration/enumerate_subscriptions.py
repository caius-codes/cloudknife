"""
Azure Subscription Enumeration Module.

Enumerates all accessible Azure subscriptions for the current user/token.
Useful for discovering scope of access and identifying high-value targets.
"""

from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_subscriptions(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all accessible Azure subscriptions.

    Uses Azure Management API to list all subscriptions the current
    token has access to.

    Requires: Token with audience https://management.azure.com/
    """
    console.print("[cyan]Enumerating Azure Subscriptions...[/cyan]")

    # Get management credential
    credential = session_mgr.get_credential(scope="management")
    if not credential:
        console.print("[red]No management credentials available.[/red]")
        console.print("[yellow]Get a token with audience 'https://management.azure.com/' first:[/yellow]")
        console.print("  - login_password")
        console.print("  - login_interactive")
        console.print("  - set_token /path/to/management_token.txt")
        return

    try:
        from azure.mgmt.subscription import SubscriptionClient
        from azure.core.exceptions import AzureError

        # Create subscription client
        subscription_client = SubscriptionClient(credential)

        console.print("[dim]Fetching subscriptions...[/dim]")

        # List all accessible subscriptions
        subscriptions: List[Dict[str, Any]] = []

        try:
            for sub in subscription_client.subscriptions.list():
                subscription_data = {
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name,
                    "state": sub.state,
                    "subscription_policies": {
                        "location_placement_id": sub.subscription_policies.location_placement_id if sub.subscription_policies else None,
                        "quota_id": sub.subscription_policies.quota_id if sub.subscription_policies else None,
                        "spending_limit": sub.subscription_policies.spending_limit if sub.subscription_policies else None,
                    },
                    "authorization_source": getattr(sub, 'authorization_source', None),
                    "tenant_id": getattr(sub, 'tenant_id', None),
                }
                subscriptions.append(subscription_data)

        except AzureError as e:
            console.print(f"[red]Azure API error: {e}[/red]")
            return
        except Exception as e:
            console.print(f"[red]Error enumerating subscriptions: {e}[/red]")
            return

        if not subscriptions:
            console.print("[yellow]No accessible subscriptions found.[/yellow]")
            console.print("[dim]This may indicate:[/dim]")
            console.print("  - User has no subscription access (tenant-level only)")
            console.print("  - Token has insufficient permissions")
            console.print("  - Subscriptions are disabled/suspended")
            return

        console.print(f"\n[green]Found {len(subscriptions)} subscription(s).[/green]\n")

        # Save enumeration data
        session_mgr.save_enumeration_data("subscriptions", subscriptions)

        # Analyze subscriptions
        active_subs = [s for s in subscriptions if s.get("state") == "Enabled"]
        disabled_subs = [s for s in subscriptions if s.get("state") != "Enabled"]

        console.print(f"[dim]Active subscriptions: {len(active_subs)}[/dim]")
        if disabled_subs:
            console.print(f"[dim]Disabled/Suspended subscriptions: {len(disabled_subs)}[/dim]")
        console.print()

        # Display subscriptions in a table
        table = Table(title=f"Azure Subscriptions - {len(subscriptions)} found")
        table.add_column("Display Name", style="cyan", no_wrap=False)
        table.add_column("Subscription ID", style="green")
        table.add_column("State", style="yellow")
        table.add_column("Quota ID", style="dim")

        for sub in subscriptions:
            display_name = sub.get("display_name", "N/A")
            subscription_id = sub.get("subscription_id", "N/A")
            state = sub.get("state", "Unknown")
            quota_id = sub.get("subscription_policies", {}).get("quota_id", "N/A")

            # Highlight state
            if state == "Enabled":
                state_display = f"[green]{state}[/green]"
            elif state in ["Disabled", "Deleted", "Warned"]:
                state_display = f"[red]{state}[/red]"
            else:
                state_display = f"[yellow]{state}[/yellow]"

            table.add_row(
                display_name,
                subscription_id,
                state_display,
                quota_id
            )

        console.print(table)

        # Show spending limit info if available
        spending_limits = []
        for sub in subscriptions:
            spending_limit = sub.get("subscription_policies", {}).get("spending_limit")
            if spending_limit and spending_limit != "Off":
                spending_limits.append((sub.get("display_name"), spending_limit))

        if spending_limits:
            console.print(f"\n[yellow]Subscriptions with spending limits:[/yellow]")
            for name, limit in spending_limits:
                console.print(f"  • {name}: {limit}")

        # Show authorization source if available
        auth_sources = {}
        for sub in subscriptions:
            auth_source = sub.get("authorization_source")
            if auth_source:
                if auth_source not in auth_sources:
                    auth_sources[auth_source] = []
                auth_sources[auth_source].append(sub.get("display_name"))

        if auth_sources:
            console.print(f"\n[cyan]Authorization sources:[/cyan]")
            for source, subs in auth_sources.items():
                console.print(f"  {source}: {len(subs)} subscription(s)")

        console.print(f"\n[dim]Saved as 'subscriptions' in enumeration data[/dim]")

        # Suggest next steps
        if active_subs:
            console.print(f"\n[cyan]💡 Next steps:[/cyan]")
            console.print(f"  - Use subscription ID with other enum commands")
            console.print(f"  - enum_resources <subscription_id>")
            console.print(f"  - enum_roles <subscription_id>")
            console.print(f"  - enum_webapps (select subscription interactively)")

    except ImportError:
        console.print("[red]Azure SDK not installed. Install: pip install azure-mgmt-subscription[/red]")
        return
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
