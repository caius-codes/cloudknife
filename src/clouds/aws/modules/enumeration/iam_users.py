from rich.console import Console
from rich.table import Table
from ...aws_session import AWSSessionManager

console = Console()


def enumerate_users(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate IAM users using paginator and save results in session.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    try:
        console.print("[bold blue]🔍 Enumerating IAM users...[/bold blue]")
        aws_sess = session_mgr.get_boto3_session()
        iam = aws_sess.client("iam")
        paginator = iam.get_paginator("list_users")

        users = []
        for page in paginator.paginate():
            for user in page.get("Users", []):
                users.append(
                    {
                        "UserName": user["UserName"],
                        "UserId": user["UserId"],
                        "Arn": user["Arn"],
                        "CreateDate": str(user["CreateDate"])[:19],
                        "Path": user["Path"],
                    }
                )

        session_mgr.save_enumeration_data("iam_users", users)

        if not users:
            console.print("[yellow]No IAM users found.[/yellow]")
            return

        table = Table(title=f"IAM Users (total: {len(users)})")
        table.add_column("UserName", style="cyan")
        table.add_column("UserId")
        table.add_column("Arn")
        table.add_column("Created")
        table.add_column("Path")

        # Nessun trunc: stampiamo i valori completi
        for u in users:
            table.add_row(
                u["UserName"],
                u["UserId"],
                u["Arn"],
                u["CreateDate"],
                u["Path"],
            )

        console.print(table)
        console.print("[green]IAM users enumeration stored in session data.[/green]")
    except Exception as e:
        console.print(f"[red]Enumeration failed: {str(e)}[/red]")
        console.print("[yellow]Ensure IAM:ListUsers permission.[/yellow]")
