from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from ...aws_session import AWSSessionManager

console = Console()


def enumerate_groups(session_mgr: AWSSessionManager, include_members: bool = False) -> None:
    """
    Enumerate IAM groups (and optionally their members).

    - Uses iam:ListGroups (paginato).
    - If include_members=True, chiama iam:GetGroup per ogni gruppo per elencare gli utenti.
    - Salva i risultati in session data sotto 'iam_groups' e 'iam_group_members'.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    console.print("[bold blue]🔍 Enumerating IAM groups...[/bold blue]")

    groups: List[Dict[str, Any]] = []

    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                groups.append(
                    {
                        "GroupName": g.get("GroupName"),
                        "GroupId": g.get("GroupId"),
                        "Arn": g.get("Arn"),
                        "Path": g.get("Path"),
                        "CreateDate": str(g.get("CreateDate", ""))[:19],
                    }
                )
    except Exception as e:
        console.print(f"[red]Failed to list IAM groups: {str(e)}[/red]")
        console.print("[yellow]Ensure iam:ListGroups permission.[/yellow]")
        return

    # Save group metadata
    session_mgr.save_enumeration_data("iam_groups", groups)

    if not groups:
        console.print("[yellow]No IAM groups found.[/yellow]")
        return

    # Group summary table
    table = Table(title=f"IAM Groups (total: {len(groups)})")
    table.add_column("GroupName", style="cyan")
    table.add_column("GroupId")
    table.add_column("Arn")
    table.add_column("Path")
    table.add_column("Created")

    for g in groups:
        table.add_row(
            g["GroupName"] or "",
            g["GroupId"] or "",
            g["Arn"] or "",
            g["Path"] or "",
            g["CreateDate"] or "",
        )

    console.print(table)

    # Optional: include members per group
    group_members: Dict[str, List[Dict[str, Any]]] = {}

    if include_members:
        console.print(
            "[bold blue]🔍 Fetching group members with iam:GetGroup (this may take a while)...[/bold blue]"
        )
        for g in groups:
            gname = g["GroupName"]
            try:
                paginator = iam.get_paginator("get_group")
                members: List[Dict[str, Any]] = []
                for page in paginator.paginate(GroupName=gname):
                    for u in page.get("Users", []):
                        members.append(
                            {
                                "UserName": u.get("UserName"),
                                "UserId": u.get("UserId"),
                                "Arn": u.get("Arn"),
                                "CreateDate": str(u.get("CreateDate", ""))[:19],
                            }
                        )
                group_members[gname] = members
            except Exception as e:
                console.print(
                    f"[red]Failed to get members for group '{gname}': {str(e)}[/red]"
                )
                console.print(
                    "[yellow]Ensure iam:GetGroup permission if you want group membership.[/yellow]"
                )

        # Also save members to session data
        session_mgr.save_enumeration_data("iam_group_members", group_members)

        # Brief summary table: group -> #members
        summary_table = Table(title="Group Membership Summary")
        summary_table.add_column("GroupName", style="cyan")
        summary_table.add_column("#Members")

        for g in groups:
            gname = g["GroupName"]
            count = len(group_members.get(gname, []))
            summary_table.add_row(gname, str(count))

        console.print(summary_table)
        console.print(
            "[dim]Full membership data stored under key 'iam_group_members' in session data.[/dim]"
        )
    else:
        # If we don't have members yet, offer a quick confirmation
        if Confirm.ask(
            "[cyan]Do you also want to fetch group members now (iam:GetGroup)?[/cyan]",
            default=False,
        ):
            enumerate_groups(session_mgr, include_members=True)
        else:
            console.print(
                "[dim]Group metadata stored under key 'iam_groups' in session data.[/dim]"
            )
