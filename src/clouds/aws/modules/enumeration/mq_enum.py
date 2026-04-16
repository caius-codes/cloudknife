from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_mq_brokers(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate Amazon MQ brokers across configured regions.

    For each region:
      - list_brokers
      - describe_broker per broker

    Stores results under 'mq_brokers' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    target_regions = resolve_regions(session_mgr, service_name="Amazon MQ")

    console.print(
        f"[bold blue]🔍 Enumerating Amazon MQ brokers in regions:[/bold blue] "
        + ", ".join(target_regions)
    )

    all_brokers: List[Dict[str, Any]] = []

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)

    for region in target_regions:
        try:
            mq = client_factory.get_client("mq", region)

            paginator = mq.get_paginator("list_brokers")
            region_brokers: List[Dict[str, Any]] = []
            for page in paginator.paginate():
                region_brokers.extend(page.get("BrokerSummaries", []))

            console.print(
                f"[green]Region {region}: found {len(region_brokers)} brokers.[/green]"
            )

            for b in region_brokers:
                broker_id = b.get("BrokerId")
                broker_name = b.get("BrokerName")
                broker_arn = b.get("BrokerArn")

                engine_type = b.get("EngineType")  # ACTIVEMQ / RABBITMQ
                broker_state = b.get("BrokerState")

                # describe_broker per info aggiuntive
                try:
                    desc = mq.describe_broker(BrokerId=broker_id)
                except Exception as e:
                    console.print(
                        f"[yellow]Failed to describe broker '{broker_name}' ({broker_id}) in {region}: {str(e)[:120]}[/yellow]"
                    )
                    all_brokers.append(
                        {
                            "BrokerId": broker_id,
                            "BrokerName": broker_name,
                            "BrokerArn": broker_arn,
                            "Region": region,
                            "EngineType": engine_type,
                            "BrokerState": broker_state,
                            "PubliclyAccessible": None,
                            "DeploymentMode": None,
                            "HostInstanceType": None,
                            "Users": None,
                            "Tags": None,
                            "DescribeOK": False,
                        }
                    )
                    continue

                publicly_accessible = desc.get("PubliclyAccessible")
                deployment_mode = desc.get("DeploymentMode")
                host_instance_type = desc.get("HostInstanceType")
                # lista utenti (solo per ActiveMQ)[web:565][web:568][web:571]
                users = desc.get("Users") or []
                user_names = [u.get("Username") for u in users if u.get("Username")]

                tags = desc.get("Tags") or {}

                all_brokers.append(
                    {
                        "BrokerId": broker_id,
                        "BrokerName": broker_name,
                        "BrokerArn": broker_arn,
                        "Region": region,
                        "EngineType": engine_type,
                        "BrokerState": broker_state,
                        "PubliclyAccessible": publicly_accessible,
                        "DeploymentMode": deployment_mode,
                        "HostInstanceType": host_instance_type,
                        "Users": user_names,
                        "Tags": tags,
                        "DescribeOK": True,
                    }
                )

        except Exception as e:
            console.print(
                f"[red]Failed to enumerate Amazon MQ brokers in region {region}: {str(e)}[/red]"
            )
            console.print(
                "[yellow]Ensure mq:ListBrokers and mq:DescribeBroker permissions for that region.[/yellow]"
            )

    session_mgr.save_enumeration_data("mq_brokers", all_brokers)

    if not all_brokers:
        console.print("[yellow]No Amazon MQ brokers found in selected regions.[/yellow]")
        return

    # Summary table
    total = len(all_brokers)
    table = Table(title=f"Amazon MQ Brokers (total: {total})")
    table.add_column("BrokerName", style="cyan")
    table.add_column("Region")
    table.add_column("Engine")
    table.add_column("State")
    table.add_column("Public")
    table.add_column("Mode")
    table.add_column("Users")
    table.add_column("DescribeOK")

    max_rows = 200
    for b in all_brokers[:max_rows]:
        users = b.get("Users") or []
        table.add_row(
            b.get("BrokerName") or "",
            b.get("Region") or "",
            b.get("EngineType") or "",
            b.get("BrokerState") or "",
            "✅" if b.get("PubliclyAccessible") else "❌",
            b.get("DeploymentMode") or "",
            str(len(users)),
            "✅" if b.get("DescribeOK") else "❌",
        )

    console.print(table)

    if total > max_rows:
        console.print(
            f"[dim]Showing first {max_rows} brokers out of {total}. "
            "Full data stored under key 'mq_brokers' in session data.[/dim]"
        )
    else:
        console.print(
            "[dim]All brokers stored under key 'mq_brokers' in session data.[/dim]"
        )
