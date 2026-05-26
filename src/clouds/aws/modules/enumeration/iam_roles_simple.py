from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager

console = Console()


def enumerate_roles_simple(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate IAM roles WITHOUT testing sts:AssumeRole.

    - Uses iam.list_roles (paginated).
    - Does NOT test assume_role permissions.
    - Faster and less invasive than full enumerate_roles.

    Saves results under 'iam_roles_simple' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold blue]🔍 Enumerating IAM roles (simple mode - no assume test)...[/bold blue]")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

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
                path = r.get("Path", "/")

                # Determine role type based on path and name
                is_service_role = path.startswith("/aws-service-role/") or role_name.startswith("AWSService")

                roles.append(
                    {
                        "RoleName": role_name,
                        "Arn": role_arn,
                        "CreateDate": create_date,
                        "MaxSessionDuration": max_session,
                        "Description": desc,
                        "Path": path,
                        "IsServiceRole": is_service_role,
                    }
                )

    except Exception as e:
        console.print(f"[red]IAM role enumeration failed: {str(e)}[/red]")
        console.print(
            "[yellow]Ensure iam:ListRoles permission.[/yellow]"
        )
        return

    session_mgr.save_enumeration_data("iam_roles_simple", roles)

    if not roles:
        console.print("[yellow]No IAM roles found.[/yellow]")
        return

    # Summary table
    table = Table(title=f"IAM Roles (total: {len(roles)})")
    table.add_column("RoleName", style="cyan")
    table.add_column("Type")
    table.add_column("Arn")
    table.add_column("MaxSession")
    table.add_column("Created")

    for r in roles:
        role_type = "🔧 Service" if r["IsServiceRole"] else "👤 Custom"
        table.add_row(
            r["RoleName"],
            role_type,
            r["Arn"],
            str(r["MaxSessionDuration"]),
            r["CreateDate"],
        )

    console.print(table)
    console.print(
        "[dim]Legend: 🔧 = AWS Service Role, 👤 = Custom Role[/dim]"
    )
    console.print(
        "[dim]💡 Tip: Use 'assume_role_session' to assume a specific role.[/dim]"
    )
