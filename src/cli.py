#!/usr/bin/env python3

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.align import Align

from .version import __version__
from .core.icons import icons

console = Console()


def print_banner(version: str = __version__):
    """Print modern CloudKnife banner using Rich panels."""

    # Main title with emojis
    title = Text(justify="center")
    title.append("☁️  ", style="bold cyan")
    title.append("C L O U D K N I F E", style="bold white on #1a1a1a")
    title.append("  🗡️", style="bold cyan")

    # Subtitle
    subtitle = Text("Multi-Cloud Penetration Testing Tool", style="dim white", justify="center")

    # Separator
    separator = Text("━" * 35, style="dim cyan", justify="center")

    # Cloud providers (using actual CLI Nerd Font icons)
    providers = Text(justify="center")
    providers.append(f"{icons.aws}", style="bold orange1")
    providers.append("AWS", style="bold orange1")
    providers.append("  •  ", style="dim white")
    providers.append(f"{icons.azure}", style="bold dodger_blue2")
    providers.append("AZURE", style="bold dodger_blue2")
    providers.append("  •  ", style="dim white")
    providers.append(f"{icons.gcp}", style="bold purple")
    providers.append("GCP", style="bold purple")

    # Combine all sections with minimal spacing
    from rich.console import Group

    content_group = Group(
        title,
        subtitle,
        separator,
        providers
    )

    # Create panel with double border
    panel = Panel(
        Align.center(content_group),
        border_style="bold cyan",
        box=box.DOUBLE_EDGE,
        title=f"[bold red]v{version}[/bold red]",
        subtitle="[bold yellow]⚡[/bold yellow] [dim red]Authorized Use ONLY[/dim red] [bold yellow]⚡[/bold yellow]",
        padding=(1, 2),
        expand=False
    )

    console.print("\n")
    console.print(panel)
    console.print("\n")

def select_cloud(current_cloud: str = "aws") -> str:
    while True:
        console.print("[bold]Select cloud provider:[/bold]")
        console.print("  [cyan]1[/cyan] - AWS")
        console.print("  [cyan]2[/cyan] - GCP")
        console.print("  [cyan]3[/cyan] - Azure")
        console.print(f"[dim]Current: {current_cloud.upper()}[/dim]")

        choice = input("Choice [1-3, ENTER to keep current]: ").strip()
        mapping = {"1": "aws", "2": "gcp", "3": "azure"}

        if choice == "":
            return current_cloud
        if choice in mapping:
            current_cloud = mapping[choice]
            console.print(f"[green]Selected cloud: {current_cloud.upper()}[/green]")
            return current_cloud

        console.print("[red]Invalid choice, please try again.[/red]")


def main() -> None:
    print_banner()
    # primo avvio: mostra sempre lo switcher
    current_cloud = select_cloud("aws")

    while True:
        cloud = current_cloud  # usa il cloud deciso

        if cloud == "aws":
            # Lazy import: carica solo quando serve
            from .clouds.aws.aws_cli import run_aws_cli
            from .clouds.aws.aws_session import AWSSessionManager
            session_mgr = AWSSessionManager("sessions/aws")
            result = run_aws_cli(session_mgr)

        elif cloud == "azure":
            # Lazy import: carica solo quando serve
            from .clouds.azure.azure_cli import run_azure_cli
            from .clouds.azure.azure_session import AzureSessionManager
            session_mgr = AzureSessionManager("sessions/azure")
            result = run_azure_cli(session_mgr)

        elif cloud == "gcp":
            # Lazy import: carica solo quando serve
            from .clouds.gcp.gcp_cli import run_gcp_cli
            from .clouds.gcp.gcp_session import GCPSessionManager
            session_mgr = GCPSessionManager("sessions/gcp")
            result = run_gcp_cli(session_mgr)

        else:
            result = "exit"

        if result == "exit":
            break

        if result in ("aws", "azure", "gcp"):
            # cloud aws / cloud azure / cloud gcp → switch diretto, senza menu
            current_cloud = result

        elif result == "switch":
            # cloud senza argomenti → apri selettore
            current_cloud = select_cloud(current_cloud)

        else:
            current_cloud = "aws"



if __name__ == "__main__":
    main()
