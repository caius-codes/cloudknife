from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def _load_ec2_cache(session_mgr: AWSSessionManager) -> List[Dict[str, Any]]:
    session_name = session_mgr.current_session
    if not session_name:
        return []
    return (
        session_mgr.enumerated_data.get(session_name, {}).get("ec2_instances", [])
        if session_name in session_mgr.enumerated_data
        else []
    )


def describe_ec2_userdata(session_mgr: AWSSessionManager, instance_id: Optional[str] = None) -> None:
    """
    Describe userData for a given InstanceId from cached 'ec2_instances' enumeration.
    If no instance_id provided, offers to dump all instances with userdata.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    ec2_cache = _load_ec2_cache(session_mgr)
    if not ec2_cache:
        console.print(
            "[yellow]No EC2 data in cache. Run 'enumerate_ec2' first to collect instances and userData.[/yellow]"
        )
        return

    # If no instance_id provided, offer bulk dump
    if not instance_id:
        instances_with_userdata = [
            inst for inst in ec2_cache
            if inst.get("HasUserData") and inst.get("UserData") and not inst.get("UserData", "").startswith("[ERROR")
        ]

        if not instances_with_userdata:
            console.print("[yellow]No EC2 instances with valid userdata found in cache.[/yellow]")
            return

        total_count = len(instances_with_userdata)
        console.print(f"[cyan]Found {total_count} EC2 instance(s) with userdata.[/cyan]")

        confirm = Prompt.ask(
            "[yellow]Do you want to dump all EC2 userdata?[/yellow]",
            choices=["y", "n"],
            default="n"
        )

        if confirm.lower() != "y":
            console.print("[yellow]Operation cancelled.[/yellow]")
            return

        # Dump all instances with userdata
        for idx, inst in enumerate(instances_with_userdata, start=1):
            remaining = total_count - idx

            ud = inst.get("UserData", "")

            meta_table = Table(title=f"EC2 Instance Metadata ({idx}/{total_count})")
            meta_table.add_column("Field", style="cyan")
            meta_table.add_column("Value")
            meta_table.add_row("InstanceId", inst.get("InstanceId", ""))
            meta_table.add_row("Name", inst.get("Name", ""))
            meta_table.add_row("State", inst.get("State", ""))
            meta_table.add_row("Type", inst.get("InstanceType", ""))
            meta_table.add_row("AZ", inst.get("AZ", ""))
            console.print(meta_table)

            console.print("[bold cyan]UserData content:[/bold cyan]")
            console.print(ud)
            console.print(
                "[dim]Inspect for secrets, credentials, configuration files, etc.[/dim]"
            )

            # Ask to continue if not the last instance
            if remaining > 0:
                continue_prompt = Prompt.ask(
                    f"\n[cyan]Continue to next instance? ({remaining} remaining)[/cyan]",
                    choices=["y", "n"],
                    default="y"
                )
                if continue_prompt.lower() != "y":
                    console.print("[yellow]Bulk dump stopped by user.[/yellow]")
                    break
                console.print()  # Add blank line between instances

        return

    # Single instance mode (instance_id provided)
    target = None
    for inst in ec2_cache:
        if inst.get("InstanceId") == instance_id:
            target = inst
            break

    if not target:
        console.print(f"[red]InstanceId '{instance_id}' not found in cached ec2_instances.[/red]")
        return

    ud = target.get("UserData") or ""
    has_ud = target.get("HasUserData", False)

    meta_table = Table(title="EC2 Instance Metadata")
    meta_table.add_column("Field", style="cyan")
    meta_table.add_column("Value")
    meta_table.add_row("InstanceId", target.get("InstanceId", ""))
    meta_table.add_row("Name", target.get("Name", ""))
    meta_table.add_row("State", target.get("State", ""))
    meta_table.add_row("Type", target.get("InstanceType", ""))
    meta_table.add_row("AZ", target.get("AZ", ""))
    meta_table.add_row("HasUserData", "Yes" if has_ud else "No")
    console.print(meta_table)

    if not has_ud or not ud or ud.startswith("[ERROR"):
        console.print("[yellow]No valid userData found for this instance (or retrieval failed).[/yellow]")
        if ud.startswith("[ERROR"):
            console.print(f"[dim]{ud}[/dim]")
        return

    console.print("[bold cyan]UserData content:[/bold cyan]")
    console.print(ud)
    console.print(
        "[dim]Inspect for secrets, credentials, configuration files, etc.[/dim]"
    )
