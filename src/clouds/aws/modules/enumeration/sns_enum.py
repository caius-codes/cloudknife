from typing import Dict, Any, List
import re

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()

ARN_TOPIC_NAME_RE = re.compile(r":topic\/(.+)$")


def _format_error_hint(e: Exception) -> str:
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "missing permissions for this service"
        return f"aws error: {code}" if code else "aws error"
    return "client / network error"


def _topic_name_from_arn(arn: str) -> str:
    m = ARN_TOPIC_NAME_RE.search(arn)
    return m.group(1) if m else arn


def sns_enum(session_mgr: AWSSessionManager, max_topics: int = 100, verbose: bool = False) -> None:
    """
    Enumerate Amazon SNS topics and subscriptions.

    For each configured region (or the default one if none configured), this module:
    - Lists SNS topics.
    - For each topic (up to max_topics per region), lists subscriptions by topic.
    - Counts topics and subscriptions per region.
    - Optionally prints per-topic details (verbose mode).

    Only uses List*/Describe* style calls with pagination.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="SNS")

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)

    console.print(
        f"[bold blue]🔔 Running sns_enum across regions:[/bold blue] "
        + ", ".join(regions)
    )

    summary: List[Dict[str, Any]] = []
    per_region_details: Dict[str, List[Dict[str, Any]]] = {}

    for region in regions:
        topics_count = 0
        subs_count = 0
        region_details: List[Dict[str, Any]] = []

        try:
            sns = client_factory.get_client("sns", region)

            seen = 0
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for t in page.get("Topics", []):
                    arn = t["TopicArn"]
                    name = _topic_name_from_arn(arn)
                    topics_count += 1
                    seen += 1

                    proto_counts: Dict[str, int] = {}
                    this_topic_subs = 0
                    perm_error = False

                    # list subscriptions by topic (best effort)
                    try:
                        sub_paginator = sns.get_paginator(
                            "list_subscriptions_by_topic"
                        )
                        for sp in sub_paginator.paginate(TopicArn=arn):
                            for sub in sp.get("Subscriptions", []):
                                p = sub.get("Protocol", "unknown")
                                proto_counts[p] = proto_counts.get(p, 0) + 1
                                this_topic_subs += 1
                        subs_count += this_topic_subs
                    except ClientError:
                        perm_error = True

                    region_details.append(
                        {
                            "name": name,
                            "arn": arn,
                            "subscriptions": this_topic_subs if not perm_error else None,
                            "protocols": proto_counts if not perm_error else {},
                            "subs_access": "OK" if not perm_error else "NO_ACCESS",
                        }
                    )

                    if seen >= max_topics:
                        break
                if seen >= max_topics:
                    break

            status = "OK" if topics_count > 0 else "EMPTY"
            if topics_count > 0:
                hint = f"topics={topics_count}, subs={subs_count}"
            else:
                hint = "no topics found"

            summary.append(
                {
                    "region": region,
                    "topics": topics_count,
                    "subscriptions": subs_count,
                    "status": status,
                    "hint": hint,
                }
            )
            per_region_details[region] = region_details

        except Exception as e:
            summary.append(
                {
                    "region": region,
                    "topics": 0,
                    "subscriptions": 0,
                    "status": "ERROR",
                    "hint": _format_error_hint(e),
                }
            )
            per_region_details[region] = []

    # ---------- Summary table ----------
    table = Table(title="SNS Enumeration Summary")
    table.add_column("Region", style="cyan")
    table.add_column("Topics")
    table.add_column("Subscriptions")
    table.add_column("Status")
    table.add_column("Hint")

    for row in summary:
        st = row.get("status", "UNKNOWN")
        if st == "OK":
            st_c = "[green]OK[/green]"
        elif st == "EMPTY":
            st_c = "[yellow]EMPTY[/yellow]"
        elif st == "ERROR":
            st_c = "[red]ERROR[/red]"
        else:
            st_c = st

        table.add_row(
            row["region"],
            str(row["topics"]),
            str(row["subscriptions"]),
            st_c,
            row["hint"],
        )

    console.print(table)

    # ---------- Verbose per-topic details ----------
    if verbose:
        for region, topics in per_region_details.items():
            if not topics:
                continue

            console.print(
                f"\n[bold magenta]Region {region} - SNS topics details[/bold magenta]"
            )
            t = Table()
            t.add_column("Name", style="cyan")
            t.add_column("Subscriptions")
            t.add_column("Protocols")
            t.add_column("Subs access")

            for topic in topics:
                if topic["subscriptions"] is None:
                    subs_str = "?"
                    protos_str = "-"
                else:
                    subs_str = str(topic["subscriptions"])
                    protos_str = ", ".join(
                        f"{p}={c}" for p, c in topic["protocols"].items()
                    ) or "-"

                t.add_row(
                    topic["name"],
                    subs_str,
                    protos_str,
                    topic["subs_access"],
                )

            console.print(t)
