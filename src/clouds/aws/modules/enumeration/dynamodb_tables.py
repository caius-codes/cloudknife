from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_dynamodb_tables(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate DynamoDB tables across configured regions.

    For each table, collects where possible:
      - Key schema (PK/SK)
      - Billing mode (on-demand vs provisioned)
      - Streams configuration
      - Encryption at rest (SSE)
      - Point-in-time recovery (PITR) status

    Stores results under 'dynamodb_tables' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    target_regions = resolve_regions(session_mgr, service_name="DynamoDB")

    console.print(
        f"[bold blue]🔍 Enumerating DynamoDB tables in regions:[/bold blue] "
        + ", ".join(target_regions)
    )

    all_tables: List[Dict[str, Any]] = []

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)

    for region in target_regions:
        try:
            ddb = client_factory.get_client("dynamodb", region)

            # 1) ListTables
            paginator = ddb.get_paginator("list_tables")
            region_table_names: List[str] = []
            for page in paginator.paginate():
                region_table_names.extend(page.get("TableNames", []))

            console.print(
                f"[green]Region {region}: found {len(region_table_names)} tables.[/green]"
            )

            # 2) DescribeTable for each (but if AccessDenied, still add the table with DescribeOK=False)
            for table_name in region_table_names:
                try:
                    desc = ddb.describe_table(TableName=table_name)["Table"]
                except Exception as e:
                    msg = str(e)
                    console.print(
                        f"[red]Failed to describe table '{table_name}' in {region}: {msg}[/red]"
                    )
                    console.print(
                        "[yellow]Ensure dynamodb:DescribeTable permission for that table.[/yellow]"
                    )
                    # Inseriamo un record “parziale” per non perdere visibilità
                    all_tables.append(
                        {
                            "TableName": table_name,
                            "Region": region,
                            "PartitionKey": "",
                            "SortKey": "",
                            "BillingMode": None,
                            "ReadCapacity": None,
                            "WriteCapacity": None,
                            "StreamEnabled": None,
                            "StreamViewType": None,
                            "Encrypted": None,
                            "PITREnabled": None,
                            "DescribeOK": False,
                        }
                    )
                    continue

                key_schema = desc.get("KeySchema", [])  # list of {AttributeName, KeyType}
                pk = next(
                    (k["AttributeName"] for k in key_schema if k.get("KeyType") == "HASH"),
                    "",
                )
                sk = next(
                    (k["AttributeName"] for k in key_schema if k.get("KeyType") == "RANGE"),
                    "",
                )

                billing_mode_summary = desc.get("BillingModeSummary", {})
                billing_mode = billing_mode_summary.get("BillingMode") or "PROVISIONED"
                provisioned = desc.get("ProvisionedThroughput", {})
                read_capacity = provisioned.get("ReadCapacityUnits") if provisioned else None
                write_capacity = provisioned.get("WriteCapacityUnits") if provisioned else None

                stream_spec = desc.get("StreamSpecification") or {}
                stream_enabled = stream_spec.get("StreamEnabled", False)
                stream_view_type = stream_spec.get("StreamViewType") if stream_enabled else None

                sse = desc.get("SSEDescription") or {}
                sse_status = sse.get("Status")
                encrypted = sse_status == "ENABLED"

                pitr_desc = desc.get("PointInTimeRecoveryDescription") or {}
                pitr_status = pitr_desc.get("PointInTimeRecoveryStatus")  # ENABLED / DISABLED
                pitr_enabled = pitr_status == "ENABLED"

                all_tables.append(
                    {
                        "TableName": table_name,
                        "Region": region,
                        "PartitionKey": pk,
                        "SortKey": sk,
                        "BillingMode": billing_mode,
                        "ReadCapacity": read_capacity,
                        "WriteCapacity": write_capacity,
                        "StreamEnabled": stream_enabled,
                        "StreamViewType": stream_view_type,
                        "Encrypted": encrypted,
                        "PITREnabled": pitr_enabled,
                        "DescribeOK": True,
                    }
                )

        except Exception as e:
            console.print(
                f"[red]Failed to enumerate DynamoDB tables in region {region}: {str(e)}[/red]"
            )
            console.print(
                "[yellow]Ensure dynamodb:ListTables and dynamodb:DescribeTable permissions for that region.[/yellow]"
            )

    session_mgr.save_enumeration_data("dynamodb_tables", all_tables)

    if not all_tables:
        console.print("[yellow]No DynamoDB tables found in selected regions.[/yellow]")
        return

    # Statistiche solo sulle tabelle con DescribeOK=True
    describable = [t for t in all_tables if t.get("DescribeOK")]
    total = len(all_tables)
    total_ok = len(describable)
    unencrypted = [t for t in describable if t.get("Encrypted") is False]
    total_unencrypted = len(unencrypted)
    pitr_on = [t for t in describable if t.get("PITREnabled")]
    total_pitr_on = len(pitr_on)

    table = Table(
        title=(
            f"DynamoDB Tables (total: {total}, described: {total_ok}, "
            f"unencrypted: {total_unencrypted}, PITR: {total_pitr_on})"
        )
    )
    table.add_column("TableName", style="cyan")
    table.add_column("Region")
    table.add_column("PK")
    table.add_column("SK")
    table.add_column("Enc")
    table.add_column("PITR")
    table.add_column("Streams")
    table.add_column("DescribeOK")

    max_rows = 200
    for t in all_tables[:max_rows]:
        streams = t.get("StreamViewType") if t.get("StreamViewType") else "-"
        enc = t.get("Encrypted")
        pitr = t.get("PITREnabled")
        table.add_row(
            t["TableName"],
            t["Region"],
            t.get("PartitionKey") or "",
            t.get("SortKey") or "",
            "✅" if enc is True else ("❌" if enc is False else "?"),
            "✅" if pitr is True else ("❌" if pitr is False else "?"),
            streams,
            "✅" if t.get("DescribeOK") else "❌",
        )

    console.print(table)

    if total > max_rows:
        console.print(
            f"[dim]Showing first {max_rows} tables out of {total}. "
            f"All data stored under key 'dynamodb_tables' in session data.[/dim]"
        )
    else:
        console.print(
            "[dim]All tables stored under key 'dynamodb_tables' in session data.[/dim]"
        )
