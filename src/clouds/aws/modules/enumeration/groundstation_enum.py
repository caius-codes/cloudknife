import datetime
from typing import Any, Dict, List

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()

# Ground Station is only available in a subset of AWS regions.
# Used to warn the user if they've configured unsupported regions.
_GS_SUPPORTED_REGIONS = {
    "us-east-2", "us-west-2",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-2",
    "eu-north-1", "eu-west-1",
    "me-south-1", "sa-east-1", "af-south-1",
}

# Statuses usable without extra required params (AVAILABLE needs groundStation/missionProfileArn/satelliteArn)
_CONTACT_STATUSES = [
    "SCHEDULED", "PASS",
    "COMPLETED", "FAILED",
    "CANCELLED", "AWS_FAILED", "AWS_CANCELLED",
]

_TZ_UTC = datetime.timezone.utc


def _fmt_err(e: Exception) -> str:
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "access denied"
        return code or "aws error"
    return str(e)[:80]


def _paginate(client, operation: str, result_key: str, **kwargs) -> List[Dict]:
    """Paginate through a Ground Station list operation and return all items."""
    items: List[Dict] = []
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def enumerate_groundstation(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate AWS Ground Station resources across configured regions.

    Collects per region (deduplicating global resources by ID):
      - Ground station sites (physical antenna locations)
      - Registered satellites
      - Mission profiles
      - Configs (antenna, tracking, dataflow, s3-recording, uplink-echo)
      - Dataflow endpoint groups
      - Contacts in a ±30-day window around now
      - Minute usage (account-level billing, fetched once)

    Saves results under 'groundstation' in session enumeration data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="Ground Station")

    unsupported = [r for r in regions if r not in _GS_SUPPORTED_REGIONS]
    if unsupported:
        console.print(
            f"[yellow]Note: Ground Station may not be available in: {', '.join(unsupported)}[/yellow]"
        )

    console.print(
        f"[bold blue]🛰  Enumerating Ground Station resources in regions: {', '.join(regions)}[/bold blue]"
    )

    client_factory = RegionalClientFactory(session_mgr)

    now = datetime.datetime.now(_TZ_UTC)
    contact_start = now - datetime.timedelta(days=30)
    contact_end = now + datetime.timedelta(days=30)
    current_month = now.month
    current_year = now.year

    # Dedup global resources (ground stations, satellites) by ID across regions
    ground_stations: Dict[str, Dict] = {}
    satellites: Dict[str, Dict] = {}

    # Regional resources — collected as flat lists with a "region" tag
    mission_profiles: List[Dict] = []
    configs: List[Dict] = []
    deg_list: List[Dict] = []
    contacts: List[Dict] = []

    minute_usage: Dict[str, Any] = {}
    minute_usage_fetched = False

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            gs = client_factory.get_client("groundstation", region)

            # ── Ground stations (global, dedup by ID) ──────────────────────────
            try:
                for item in _paginate(gs, "list_ground_stations", "groundStationList"):
                    ground_stations[item["groundStationId"]] = item
            except ClientError as e:
                console.print(f"[dim]  list_ground_stations: {_fmt_err(e)}[/dim]")

            # ── Satellites (global, dedup by ID) ───────────────────────────────
            try:
                for item in _paginate(gs, "list_satellites", "satellites"):
                    satellites[item["satelliteId"]] = item
            except ClientError as e:
                console.print(f"[dim]  list_satellites: {_fmt_err(e)}[/dim]")

            # ── Mission profiles (regional) ────────────────────────────────────
            try:
                for item in _paginate(gs, "list_mission_profiles", "missionProfileList"):
                    mission_profiles.append({**item, "_region": region})
            except ClientError as e:
                console.print(f"[dim]  list_mission_profiles: {_fmt_err(e)}[/dim]")

            # ── Configs (regional) ─────────────────────────────────────────────
            try:
                for item in _paginate(gs, "list_configs", "configList"):
                    configs.append({**item, "_region": region})
            except ClientError as e:
                console.print(f"[dim]  list_configs: {_fmt_err(e)}[/dim]")

            # ── Dataflow endpoint groups (regional) ────────────────────────────
            try:
                for item in _paginate(gs, "list_dataflow_endpoint_groups", "dataflowEndpointGroupList"):
                    deg_list.append({**item, "_region": region})
            except ClientError as e:
                console.print(f"[dim]  list_dataflow_endpoint_groups: {_fmt_err(e)}[/dim]")

            # ── Contacts (regional, ±30-day window) ───────────────────────────
            try:
                for item in _paginate(
                    gs, "list_contacts", "contactList",
                    startTime=contact_start,
                    endTime=contact_end,
                    statusList=_CONTACT_STATUSES,
                ):
                    contacts.append({**item, "_region": region})
            except ClientError as e:
                console.print(f"[dim]  list_contacts: {_fmt_err(e)}[/dim]")

            # ── Minute usage (account-level, fetch once) ───────────────────────
            if not minute_usage_fetched:
                try:
                    resp = gs.get_minute_usage(month=current_month, year=current_year)
                    minute_usage = {
                        "estimated_minutes_remaining": resp.get("estimatedMinutesRemaining"),
                        "is_reserved_minutes_customer": resp.get("isReservedMinutesCustomer"),
                        "total_reserved_minute_allocation": resp.get("totalReservedMinuteAllocation"),
                        "total_scheduled_minutes": resp.get("totalScheduledMinutes"),
                        "upcoming_contacts_count": resp.get("upcomingContactsCount"),
                    }
                    minute_usage_fetched = True
                except ClientError as e:
                    console.print(f"[dim]  get_minute_usage: {_fmt_err(e)}[/dim]")

        except Exception as e:
            console.print(f"[red]  Ground Station unavailable in {region}: {_fmt_err(e)}[/red]")

    gs_list = list(ground_stations.values())
    sat_list = list(satellites.values())

    # ── Persist ────────────────────────────────────────────────────────────────
    session_mgr.save_enumeration_data("groundstation", {
        "ground_stations": gs_list,
        "satellites": sat_list,
        "mission_profiles": mission_profiles,
        "configs": configs,
        "dataflow_endpoint_groups": deg_list,
        "contacts": contacts,
        "minute_usage": minute_usage,
        "regions_scanned": regions,
        "contact_window": {
            "from": contact_start.isoformat(),
            "to": contact_end.isoformat(),
        },
    })

    # ── Display ────────────────────────────────────────────────────────────────
    total = (
        len(gs_list) + len(sat_list) + len(mission_profiles)
        + len(configs) + len(deg_list) + len(contacts)
    )
    if total == 0 and not minute_usage:
        console.print(
            "[yellow]No Ground Station resources found. "
            "Service may not be enabled in any configured region.[/yellow]"
        )
        return

    # Summary
    summary = Table(title="Ground Station — Summary", show_lines=False)
    summary.add_column("Resource", style="cyan")
    summary.add_column("Count", justify="right")
    summary.add_column("Note", style="dim")
    summary.add_row("Ground stations", str(len(gs_list)), "physical antenna sites (global)")
    summary.add_row("Satellites", str(len(sat_list)), "registered in account (global)")
    summary.add_row("Mission profiles", str(len(mission_profiles)), "contact configurations (regional)")
    summary.add_row("Configs", str(len(configs)), "antenna / tracking / dataflow / recording")
    summary.add_row("Dataflow endpoint groups", str(len(deg_list)), "data routing targets")
    summary.add_row(
        "Contacts",
        str(len(contacts)),
        f"window: {contact_start.strftime('%Y-%m-%d')} → {contact_end.strftime('%Y-%m-%d')}",
    )
    console.print(summary)

    if minute_usage:
        console.print(
            f"\n[bold]Minute usage ({current_month}/{current_year}):[/bold]"
            f"  reserved={minute_usage.get('total_reserved_minute_allocation', 'N/A')}"
            f"  scheduled={minute_usage.get('total_scheduled_minutes', 'N/A')}"
            f"  remaining={minute_usage.get('estimated_minutes_remaining', 'N/A')}"
            f"  upcoming contacts={minute_usage.get('upcoming_contacts_count', 'N/A')}"
            f"  reserved customer={minute_usage.get('is_reserved_minutes_customer', 'N/A')}"
        )

    # Satellites
    if sat_list:
        t = Table(title=f"Satellites ({len(sat_list)})")
        t.add_column("SatelliteId", style="cyan")
        t.add_column("NORAD ID", justify="right")
        t.add_column("ARN", style="dim")
        t.add_column("Ground Stations")
        for s in sat_list:
            t.add_row(
                s.get("satelliteId", ""),
                str(s.get("noradSatelliteID", "")),
                s.get("satelliteArn", ""),
                ", ".join(s.get("groundStations", [])),
            )
        console.print(t)

    # Ground stations
    if gs_list:
        t = Table(title=f"Ground Stations ({len(gs_list)})")
        t.add_column("ID", style="cyan")
        t.add_column("Name")
        t.add_column("Region")
        for g in gs_list:
            t.add_row(
                g.get("groundStationId", ""),
                g.get("groundStationName", ""),
                g.get("region", ""),
            )
        console.print(t)

    # Mission profiles
    if mission_profiles:
        t = Table(title=f"Mission Profiles ({len(mission_profiles)})")
        t.add_column("ID", style="cyan")
        t.add_column("Name")
        t.add_column("Region")
        t.add_column("ARN", style="dim")
        for mp in mission_profiles:
            t.add_row(
                mp.get("missionProfileId", ""),
                mp.get("name", ""),
                mp.get("_region", ""),
                mp.get("missionProfileArn", ""),
            )
        console.print(t)

    # Configs
    if configs:
        t = Table(title=f"Configs ({len(configs)})")
        t.add_column("ID", style="cyan")
        t.add_column("Name")
        t.add_column("Type")
        t.add_column("Region")
        t.add_column("ARN", style="dim")
        for c in configs:
            t.add_row(
                c.get("configId", ""),
                c.get("name", ""),
                c.get("configType", ""),
                c.get("_region", ""),
                c.get("configArn", ""),
            )
        console.print(t)

    # Dataflow endpoint groups
    if deg_list:
        t = Table(title=f"Dataflow Endpoint Groups ({len(deg_list)})")
        t.add_column("ID", style="cyan")
        t.add_column("Region")
        t.add_column("ARN", style="dim")
        for d in deg_list:
            t.add_row(
                d.get("dataflowEndpointGroupId", ""),
                d.get("_region", ""),
                d.get("dataflowEndpointGroupArn", ""),
            )
        console.print(t)

    # Contacts
    if contacts:
        _epoch = datetime.datetime.fromtimestamp(0, tz=_TZ_UTC)
        contacts_sorted = sorted(
            contacts,
            key=lambda c: c.get("startTime") or _epoch,
            reverse=True,
        )
        display_contacts = contacts_sorted[:50]

        t = Table(title=f"Contacts — last/next 30 days ({len(contacts)} total, showing {len(display_contacts)})")
        t.add_column("ContactId", style="cyan")
        t.add_column("Status")
        t.add_column("Start (UTC)")
        t.add_column("End (UTC)")
        t.add_column("Satellite")
        t.add_column("Ground Station")
        t.add_column("Region")

        for c in display_contacts:
            status = c.get("contactStatus", "")
            if status in ("SCHEDULED", "PASS"):
                status_fmt = f"[green]{status}[/green]"
            elif status in ("FAILED", "AWS_FAILED", "CANCELLED", "AWS_CANCELLED"):
                status_fmt = f"[red]{status}[/red]"
            else:
                status_fmt = status

            start = c.get("startTime")
            end = c.get("endTime")
            start_str = start.strftime("%Y-%m-%d %H:%M") if hasattr(start, "strftime") else str(start)
            end_str = end.strftime("%H:%M") if hasattr(end, "strftime") else str(end)

            sat_arn = c.get("satelliteArn", "")
            sat_id = sat_arn.split("/")[-1] if "/" in sat_arn else sat_arn

            t.add_row(
                c.get("contactId", ""),
                status_fmt,
                start_str,
                end_str,
                sat_id,
                c.get("groundStation", ""),
                c.get("_region", ""),
            )

        console.print(t)
        if len(contacts) > 50:
            console.print(f"[dim]Showing 50 of {len(contacts)} contacts. Full data saved in session.[/dim]")

    console.print(
        "[green]Ground Station enumeration complete. "
        "Data saved under 'groundstation' in session.[/green]"
    )
