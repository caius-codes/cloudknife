"""GCP module search command."""

from typing import Optional

from rich.console import Console
from rich.table import Table

from src.core.module_registry import ModuleRegistry

console = Console()
_registry: Optional[ModuleRegistry] = None


def search_modules(session_mgr, query: Optional[str]) -> None:
    """
    Search GCP modules by keyword.

    Searches across module names, docstrings, and categories using substring matching.
    Results are ranked by relevance (name match > docstring match > category match).

    Args:
        session_mgr: GCP session manager instance (unused but required for CLI consistency)
        query: Search keyword (case-insensitive)

    Usage:
        search <keyword>

    Examples:
        search jwt
        search service account
        search cloud run
    """
    global _registry

    if not query:
        console.print("[yellow]Usage: search <keyword>[/yellow]")
        console.print("[dim]Example: search jwt[/dim]")
        return

    if _registry is None:
        console.print("[dim]Building module index...[/dim]")
        try:
            _registry = ModuleRegistry.discover("gcp")
        except Exception as e:
            console.print(f"[red]Error building module index: {e}[/red]")
            return

    results = _registry.search(query)

    if not results:
        console.print(f"[yellow]No modules found matching '{query}'[/yellow]")
        console.print("[dim]Try: 'service account', 'jwt', 'cloud run', 'storage', 'enumerate'[/dim]")
        return

    table = Table(title=f"GCP Modules matching '{query}' ({len(results)} found)")
    table.add_column("Command", style="bold cyan", no_wrap=True)
    table.add_column("Category", style="dim")
    table.add_column("Description")

    for mod in results:
        desc = mod.docstring[:80] + "..." if len(mod.docstring) > 80 else mod.docstring
        table.add_row(mod.name, mod.category, desc)

    console.print(table)
    console.print("\n[dim]Type the command name to run it, or 'help' for more info.[/dim]")
