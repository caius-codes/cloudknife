import json
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def _get_cached_tables(session_mgr: AWSSessionManager) -> List[Dict[str, Any]]:
    session_name = session_mgr.current_session
    if not session_name:
        return []
    return (
        session_mgr.enumerated_data.get(session_name, {}).get("dynamodb_tables", [])
        if session_name in session_mgr.enumerated_data
        else []
    )


def describe_dynamodb_table(session_mgr: AWSSessionManager, table_name: Optional[str] = None) -> None:
    """
    Describe detailed information (DescribeTable JSON) for a specific DynamoDB table.

    - Uses cached 'dynamodb_tables' to infer region and basic metadata.
    - Calls dynamodb:DescribeTable once and prints:
      - A small metadata table
      - Full DescribeTable JSON pretty-printed
    - Stores a JSON-serializable copy under 'dynamodb_table_details' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not table_name:
        table_name = Prompt.ask("[cyan]DynamoDB TableName[/cyan]")

    if not table_name:
        console.print("[red]Empty table name, aborting.[/red]")
        return

    cached = _get_cached_tables(session_mgr)
    if not cached:
        console.print(
            "[yellow]No cached DynamoDB tables in this session. "
            "Run 'enumerate_dynamodb' first for better context.[/yellow]"
        )

    # Try to find the table in the cache
    cached_entry: Optional[Dict[str, Any]] = None
    for t in cached:
        if t.get("TableName") == table_name:
            cached_entry = t
            break

    region = None
    if cached_entry:
        region = cached_entry.get("Region")

    if not region:
        # Fallback: usa default region
        region = session_mgr.current_session_data.get("region")

    if not region:
        console.print(
            "[red]Unable to determine region for that table. "
            "Set a default region with 'set_regions' or re-run enumeration.[/red]"
        )
        return

    console.print(
        f"[bold blue]🔍 Fetching DynamoDB DescribeTable for '{table_name}' in region {region}...[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    ddb = aws_sess.client("dynamodb", region_name=region)

    try:
        resp = ddb.describe_table(TableName=table_name)
        table_desc = resp.get("Table", {})
    except Exception as e:
        console.print(f"[red]Failed to describe table '{table_name}': {str(e)}[/red]")
        console.print(
            "[yellow]Ensure dynamodb:DescribeTable permission on that table.[/yellow]"
        )
        return

    # Summary metadata table
    key_schema = table_desc.get("KeySchema", [])
    pk = next(
        (k["AttributeName"] for k in key_schema if k.get("KeyType") == "HASH"),
        "",
    )
    sk = next(
        (k["AttributeName"] for k in key_schema if k.get("KeyType") == "RANGE"),
        "",
    )

    billing_mode_summary = table_desc.get("BillingModeSummary", {})
    billing_mode = billing_mode_summary.get("BillingMode") or "PROVISIONED"
    provisioned = table_desc.get("ProvisionedThroughput", {})
    read_capacity = provisioned.get("ReadCapacityUnits") if provisioned else None
    write_capacity = provisioned.get("WriteCapacityUnits") if provisioned else None

    stream_spec = table_desc.get("StreamSpecification") or {}
    stream_enabled = stream_spec.get("StreamEnabled", False)
    stream_view_type = stream_spec.get("StreamViewType") if stream_enabled else None

    sse = table_desc.get("SSEDescription") or {}
    sse_status = sse.get("Status")
    encrypted = sse_status == "ENABLED"

    pitr_desc = table_desc.get("PointInTimeRecoveryDescription") or {}
    pitr_status = pitr_desc.get("PointInTimeRecoveryStatus")
    pitr_enabled = pitr_status == "ENABLED"

    meta = Table(title=f"DynamoDB Table Metadata: {table_name}")
    meta.add_column("Field", style="cyan")
    meta.add_column("Value")

    meta.add_row("Region", region)
    meta.add_row("PartitionKey", pk)
    meta.add_row("SortKey", sk or "-")
    meta.add_row("BillingMode", billing_mode)
    if billing_mode == "PROVISIONED":
        meta.add_row("ReadCapacity", str(read_capacity or ""))
        meta.add_row("WriteCapacity", str(write_capacity or ""))
    meta.add_row("Encrypted (SSE)", "Yes" if encrypted else "No")
    meta.add_row("PITR Enabled", "Yes" if pitr_enabled else "No")
    if stream_enabled:
        meta.add_row("Streams", f"Enabled ({stream_view_type})")
    else:
        meta.add_row("Streams", "Disabled")

    console.print(meta)

    # JSON completo pretty (convertiamo datetime ecc. in stringa solo per la stampa)
    console.print("[bold cyan]DescribeTable JSON:[/bold cyan]")
    pretty = json.dumps(table_desc, indent=2, default=str)
    console.print(pretty)

    # Normalize for session storage (datetime/Decimal -> str)
    def _normalize(obj: Any) -> Any:
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        if isinstance(obj, (list, tuple)):
            return [_normalize(x) for x in obj]
        if isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()}
        # datetime, Decimal, altri tipi complessi
        return str(obj)

    normalized_desc = _normalize(table_desc)

    # Salviamo in session data per reference
    session_mgr.save_enumeration_data(
        "dynamodb_table_details",
        {"TableName": table_name, "Region": region, "DescribeTable": normalized_desc},
    )

    console.print(
        "[green]DescribeTable result stored under key 'dynamodb_table_details' in session data.[/green]"
    )
