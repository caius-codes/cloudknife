"""
AWS IAM Privilege Escalation Path Analysis.

Analyzes IAM bruteforce results to identify potential privilege escalation paths
based on available permissions. Maps discovered permissions to known exploitation
techniques from security research.
"""

from typing import List, Dict, Set, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager
from src.data.aws_privesc_techniques import AWS_PRIVESC_TECHNIQUES


console = Console()


def analyze_privilege_escalation(
    session_mgr: AWSSessionManager,
    scan_type: str = "quick",
    severity_filter: Optional[str] = None
) -> None:
    """
    Analyze IAM permissions to identify privilege escalation paths.

    Args:
        session_mgr: AWS session manager instance
        scan_type: Analysis depth - "quick" (permission-based) or "deep" (not implemented)
        severity_filter: Filter by severity - "CRITICAL", "HIGH", "MEDIUM", "LOW" (optional)
    """
    console.print("\n[bold cyan]AWS Privilege Escalation Path Analysis[/bold cyan]")
    console.print("[dim]Analyzing IAM permissions for privilege escalation opportunities...[/dim]\n")

    # Step 1: Load permissions from bruteforce session data
    console.print("[cyan]→[/cyan] Loading IAM bruteforce results from session...")

    bruteforce_data = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("iam_bruteforce", [])

    if not bruteforce_data:
        console.print(
            "[yellow]⚠️  No IAM bruteforce data found in current session.[/yellow]\n"
            "[dim]Run 'enumerate_bruteforce_permissions iam fast' first to test permissions.[/dim]"
        )
        return

    # Step 2: Extract ALLOWED permissions
    allowed_perms = _load_allowed_permissions(bruteforce_data)

    if not allowed_perms:
        console.print(
            "[yellow]⚠️  No ALLOWED permissions found in bruteforce results.[/yellow]\n"
            "[dim]The current credentials may have very restricted permissions.[/dim]"
        )
        return

    console.print(f"[green]✓[/green] Found {len(allowed_perms)} ALLOWED permissions\n")

    # Step 3: Check each escalation technique
    console.print("[cyan]→[/cyan] Checking against 22 privilege escalation techniques...")

    escalation_paths = _identify_escalation_paths(allowed_perms, severity_filter)

    # Step 4: Sort by severity and completeness
    escalation_paths = _sort_escalation_paths(escalation_paths)

    # Step 5: Save to session
    session_data = {
        "scan_type": scan_type,
        "total_permissions": len(allowed_perms),
        "total_paths": len(escalation_paths),
        "complete_paths": len([p for p in escalation_paths if p["is_complete"]]),
        "partial_paths": len([p for p in escalation_paths if not p["is_complete"]]),
        "escalation_paths": escalation_paths,
    }

    session_mgr.save_enumeration_data("privilege_escalation_paths", session_data)

    # Step 6: Display results
    if escalation_paths:
        _display_escalation_paths(escalation_paths, scan_type)
    else:
        console.print(
            "[green]✓ No privilege escalation paths detected.[/green]\n"
            "[dim]The current permissions do not match known escalation techniques.[/dim]"
        )


def _load_allowed_permissions(bruteforce_data: List[Dict[str, Any]]) -> Set[str]:
    """
    Extract ALLOWED permissions from bruteforce results.

    Args:
        bruteforce_data: List of bruteforce test results

    Returns:
        Set of permission strings in format "service:Action"
    """
    allowed_perms = set()

    for result in bruteforce_data:
        if result.get("status") == "ALLOWED":
            service = result.get("service", "")
            action = result.get("action", "")

            if service and action:
                # Format: service:Action (e.g., "iam:CreateUser")
                perm = f"{service}:{action}"
                allowed_perms.add(perm)

    return allowed_perms


def _identify_escalation_paths(
    allowed_perms: Set[str],
    severity_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Match available permissions against escalation techniques.

    Args:
        allowed_perms: Set of ALLOWED permissions
        severity_filter: Optional severity filter

    Returns:
        List of identified escalation paths with metadata
    """
    escalation_paths = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for technique in AWS_PRIVESC_TECHNIQUES:
        required = set(technique["required_permissions"])
        available = required.intersection(allowed_perms)
        missing = required - allowed_perms
        has_all = required.issubset(allowed_perms)

        # Include if we have ALL permissions OR some partial match
        if has_all or len(available) > 0:
            # Apply severity filter if specified
            if severity_filter:
                if severity_order.get(technique["severity"], 99) > severity_order.get(severity_filter, 0):
                    continue

            path = {
                "technique": technique,
                "available_permissions": sorted(list(available)),
                "missing_permissions": sorted(list(missing)),
                "is_complete": has_all,
                "match_percentage": int((len(available) / len(required)) * 100) if required else 0,
                "exploitation_command": technique["exploitation_steps"][0] if technique["exploitation_steps"] else ""
            }

            escalation_paths.append(path)

    return escalation_paths


def _sort_escalation_paths(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort escalation paths by severity (highest first) and completeness.

    Args:
        paths: List of escalation paths

    Returns:
        Sorted list of escalation paths
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def sort_key(path):
        tech = path["technique"]
        severity_val = severity_order.get(tech["severity"], 99)
        # Complete paths first (0), then partial (1)
        completeness_val = 0 if path["is_complete"] else 1
        # Higher match percentage comes first (negate for descending)
        match_val = -path["match_percentage"]

        return (severity_val, completeness_val, match_val)

    return sorted(paths, key=sort_key)


def _display_escalation_paths(paths: List[Dict[str, Any]], scan_type: str) -> None:
    """
    Display escalation paths in formatted Rich tables.

    Args:
        paths: List of identified escalation paths
        scan_type: Type of scan performed
    """
    # Display summary panel
    _display_summary_panel(paths)

    # Display detailed paths table
    _display_paths_table(paths)

    # Display critical complete paths with exploitation steps
    _display_critical_paths(paths)


def _display_summary_panel(paths: List[Dict[str, Any]]) -> None:
    """Display summary statistics panel."""
    total = len(paths)
    complete = len([p for p in paths if p["is_complete"]])
    partial = len([p for p in paths if not p["is_complete"]])

    # Count by severity
    by_severity = {}
    for p in paths:
        sev = p["technique"]["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Build summary table
    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="cyan", justify="right")
    summary_table.add_column()

    summary_table.add_row("Total Paths:", f"[bold]{total}[/bold]")
    summary_table.add_row("├─ Complete:", f"[green]{complete}[/green]")
    summary_table.add_row("└─ Partial:", f"[yellow]{partial}[/yellow]")
    summary_table.add_row("", "")

    # Add severity breakdown
    if by_severity.get("CRITICAL", 0) > 0:
        summary_table.add_row("CRITICAL:", f"[red bold]{by_severity['CRITICAL']}[/red bold]")
    if by_severity.get("HIGH", 0) > 0:
        summary_table.add_row("HIGH:", f"[yellow]{by_severity['HIGH']}[/yellow]")
    if by_severity.get("MEDIUM", 0) > 0:
        summary_table.add_row("MEDIUM:", f"[blue]{by_severity['MEDIUM']}[/blue]")
    if by_severity.get("LOW", 0) > 0:
        summary_table.add_row("LOW:", f"[dim]{by_severity['LOW']}[/dim]")

    console.print(Panel(
        summary_table,
        title="[bold cyan]Privilege Escalation Summary[/bold cyan]",
        border_style="cyan"
    ))
    console.print()


def _display_paths_table(paths: List[Dict[str, Any]]) -> None:
    """Display detailed escalation paths table."""
    table = Table(
        title="Privilege Escalation Paths (Sorted by Severity)",
        show_header=True,
        header_style="bold cyan"
    )

    table.add_column("Severity", style="cyan", width=10)
    table.add_column("Technique", style="bold", width=35)
    table.add_column("Status", width=12)
    table.add_column("Match", justify="right", width=8)
    table.add_column("Category", width=20)

    for path in paths:
        tech = path["technique"]

        # Severity with color
        sev_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "dim"
        }.get(tech["severity"], "white")

        severity_display = f"[{sev_color} bold]{tech['severity']}[/{sev_color} bold]"

        # Status with color
        if path["is_complete"]:
            status_display = "[green bold]COMPLETE[/green bold]"
        else:
            status_display = f"[yellow]PARTIAL[/yellow]"

        # Match percentage
        match_display = f"[cyan]{path['match_percentage']}%[/cyan]"

        # Category
        category_display = tech["category"].replace("_", " ").title()

        table.add_row(
            severity_display,
            tech["name"],
            status_display,
            match_display,
            category_display
        )

    console.print(table)
    console.print()


def _display_critical_paths(paths: List[Dict[str, Any]]) -> None:
    """Display top critical complete paths with exploitation details."""
    # Filter for CRITICAL complete paths
    critical_complete = [
        p for p in paths
        if p["technique"]["severity"] == "CRITICAL" and p["is_complete"]
    ]

    if not critical_complete:
        return

    # Show top 5 critical paths
    top_paths = critical_complete[:5]

    console.print("[bold red]🚨 Critical Privilege Escalation Paths (Fully Exploitable)[/bold red]\n")

    for i, path in enumerate(top_paths, 1):
        tech = path["technique"]

        console.print(f"[bold red]{i}. {tech['name']}[/bold red]")
        console.print(f"   [dim]{tech['description']}[/dim]")
        console.print(f"   [cyan]Target:[/cyan] {tech['target']}")
        console.print(f"   [cyan]Required Permissions:[/cyan]")

        for perm in tech["required_permissions"]:
            console.print(f"      • [green]{perm}[/green] ✓")

        console.print(f"   [cyan]Exploitation Steps:[/cyan]")

        for j, step in enumerate(tech["exploitation_steps"], 1):
            # Truncate long commands
            if len(step) > 100:
                step_display = step[:97] + "..."
            else:
                step_display = step
            console.print(f"      {j}. [yellow]{step_display}[/yellow]")

        if tech.get("references"):
            console.print(f"   [cyan]References:[/cyan] {tech['references'][0]}")

        console.print()

    if len(critical_complete) > 5:
        console.print(f"[dim]... and {len(critical_complete) - 5} more critical paths[/dim]\n")

    # Display warning
    console.print(
        "[bold red]⚠️  WARNING:[/bold red] These paths represent fully exploitable privilege escalation vectors.\n"
        "[dim]Review IAM policies to understand why these permissions are granted.[/dim]\n"
    )


def analyze_privilege_escalation_paths(session_mgr: AWSSessionManager) -> None:
    """
    Analyze and display privilege escalation paths from session.

    Args:
        session_mgr: AWS session manager instance
    """
    console.print("\n[bold cyan]Previously Analyzed Privilege Escalation Paths[/bold cyan]\n")

    # Load from session
    session_data = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("privilege_escalation_paths", None)

    if not session_data:
        console.print(
            "[yellow]⚠️  No privilege escalation analysis found in current session.[/yellow]\n"
            "[dim]Run 'analyze_privesc' first to identify escalation paths.[/dim]"
        )
        return

    paths = session_data.get("escalation_paths", [])
    scan_type = session_data.get("scan_type", "quick")

    if not paths:
        console.print(
            "[green]✓ No privilege escalation paths were detected in previous analysis.[/green]"
        )
        return

    # Display paths
    _display_escalation_paths(paths, scan_type)
