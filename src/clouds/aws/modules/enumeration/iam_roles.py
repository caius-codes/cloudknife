from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager

console = Console()


def enumerate_roles(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate IAM roles and check if current identity can assume each role.

    - Uses iam.list_roles (paginato).
    - For each role, attempts sts.assume_role with short duration.
    - Does NOT persist temporary creds, only records ALLOWED / DENIED / ERROR.

    Saves results under 'iam_roles' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold blue]🔍 Enumerating IAM roles and testing sts:AssumeRole...[/bold blue]")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")
    sts = aws_sess.client("sts")

    roles: List[Dict[str, Any]] = []

    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                role_name = r["RoleName"]
                role_arn = r["Arn"]
                create_date = str(r.get("CreateDate", ""))[:19]
                max_session = r.get("MaxSessionDuration", "")
                desc = r.get("Description", "")

                assume_status = "UNKNOWN"
                assume_error = ""

                try:
                    sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName="cloudknife-enum",
                        DurationSeconds=900,
                    )
                    assume_status = "ALLOWED"
                except Exception as e:
                    msg = str(e)
                    assume_error = msg[:200]
                    if "AccessDenied" in msg or "not authorized" in msg or "Not authorized" in msg:
                        assume_status = "DENIED"
                    else:
                        assume_status = "ERROR"

                roles.append(
                    {
                        "RoleName": role_name,
                        "Arn": role_arn,
                        "CreateDate": create_date,
                        "MaxSessionDuration": max_session,
                        "Description": desc,
                        "AssumeStatus": assume_status,
                        "AssumeError": assume_error,
                    }
                )

    except Exception as e:
        console.print(f"[red]IAM role enumeration failed: {str(e)}[/red]")
        console.print(
            "[yellow]Ensure iam:ListRoles and sts:AssumeRole permissions (for testing assume).[/yellow]"
        )
        return

    session_mgr.save_enumeration_data("iam_roles", roles)

    if not roles:
        console.print("[yellow]No IAM roles found.[/yellow]")
        return

    # Summary table (Arn instead of Path)
    table = Table(title=f"IAM Roles (total: {len(roles)})")
    table.add_column("RoleName", style="cyan")
    table.add_column("CanAssume")
    table.add_column("Arn")
    table.add_column("MaxSession")
    table.add_column("Created")

    for r in roles:
        status = r["AssumeStatus"]
        if status == "ALLOWED":
            flag = "✅"
        elif status == "DENIED":
            flag = "❌"
        else:
            flag = "⚠️"
        table.add_row(
            r["RoleName"],
            flag,
            r["Arn"],
            str(r["MaxSessionDuration"]),
            r["CreateDate"],
        )

    console.print(table)
    console.print(
        "[dim]Legend: ✅ = sts:AssumeRole succeeded, ❌ = AccessDenied, "
        "⚠️ = other error (see 'iam_roles' in session data).[/dim]"
    )
