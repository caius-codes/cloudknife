from typing import Any, Dict, List

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def _fmt_err(e: Exception) -> str:
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "access denied"
        return code or "aws error"
    return str(e)[:80]


def _paginate_eb(client, operation: str, result_key: str, **kwargs) -> List[Dict]:
    """Paginate an Elastic Beanstalk list/describe operation via NextToken."""
    items: List[Dict] = []
    next_token = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        resp = getattr(client, operation)(**params)
        items.extend(resp.get(result_key, []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


_HEALTH_COLOR = {
    "Green": "[green]Green[/green]",
    "Yellow": "[yellow]Yellow[/yellow]",
    "Red": "[red]Red[/red]",
    "Grey": "[dim]Grey[/dim]",
}


def enumerate_elasticbeanstalk(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate Elastic Beanstalk applications, environments, and application versions.

    Per region collects:
      - Applications (name, description, creation date, env count, version count)
      - Environments (name, app, health, status, URL, running version, solution stack)
      - Application versions (label, app, status, creation date)

    Saves results under 'elasticbeanstalk' in session enumeration data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="Elastic Beanstalk")
    client_factory = RegionalClientFactory(session_mgr)

    console.print(
        f"[bold blue]🪲  Enumerating Elastic Beanstalk in regions: {', '.join(regions)}[/bold blue]"
    )

    all_data: Dict[str, Any] = {}

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            eb = client_factory.get_client("elasticbeanstalk", region)

            # ── Applications ──────────────────────────────────────────────────
            apps: List[Dict] = []
            try:
                apps = eb.describe_applications().get("Applications", [])
            except ClientError as e:
                console.print(f"[dim]  describe_applications: {_fmt_err(e)}[/dim]")

            # ── Environments ──────────────────────────────────────────────────
            envs: List[Dict] = []
            try:
                envs = _paginate_eb(eb, "describe_environments", "Environments")
            except ClientError as e:
                console.print(f"[dim]  describe_environments: {_fmt_err(e)}[/dim]")

            # ── Application versions ──────────────────────────────────────────
            versions: List[Dict] = []
            try:
                versions = _paginate_eb(eb, "describe_application_versions", "ApplicationVersions")
            except ClientError as e:
                console.print(f"[dim]  describe_application_versions: {_fmt_err(e)}[/dim]")

            all_data[region] = {
                "applications": apps,
                "environments": envs,
                "versions": versions,
            }

        except Exception as e:
            console.print(f"[red]  Elastic Beanstalk unavailable in {region}: {_fmt_err(e)}[/red]")
            all_data[region] = {"applications": [], "environments": [], "versions": []}

    # ── Persist ────────────────────────────────────────────────────────────────
    session_mgr.save_enumeration_data("elasticbeanstalk", {
        "regions": all_data,
        "regions_scanned": regions,
    })

    # ── Display ────────────────────────────────────────────────────────────────
    total_apps = sum(len(d["applications"]) for d in all_data.values())
    total_envs = sum(len(d["environments"]) for d in all_data.values())
    total_vers = sum(len(d["versions"]) for d in all_data.values())

    if total_apps == 0 and total_envs == 0:
        console.print(
            "[yellow]No Elastic Beanstalk resources found in any configured region.[/yellow]"
        )
        return

    # Summary table
    summary = Table(title="Elastic Beanstalk — Summary")
    summary.add_column("Region", style="cyan")
    summary.add_column("Applications", justify="right")
    summary.add_column("Environments", justify="right")
    summary.add_column("Versions", justify="right")
    for region, d in all_data.items():
        summary.add_row(
            region,
            str(len(d["applications"])),
            str(len(d["environments"])),
            str(len(d["versions"])),
        )
    console.print(summary)

    # Environments table (main view — most useful for pentest)
    all_envs = [
        {**env, "_region": region}
        for region, d in all_data.items()
        for env in d["environments"]
    ]
    if all_envs:
        t = Table(title=f"Environments ({total_envs} total)")
        t.add_column("Name", style="cyan")
        t.add_column("Application")
        t.add_column("Health")
        t.add_column("Status")
        t.add_column("Version")
        t.add_column("URL", style="dim")
        t.add_column("Region")

        for env in all_envs:
            health_raw = env.get("Health", "")
            health_fmt = _HEALTH_COLOR.get(health_raw, health_raw)
            url = env.get("CNAME", env.get("EndpointURL", ""))
            t.add_row(
                env.get("EnvironmentName", ""),
                env.get("ApplicationName", ""),
                health_fmt,
                env.get("Status", ""),
                env.get("VersionLabel", ""),
                url,
                env.get("_region", ""),
            )
        console.print(t)

    # Applications table
    all_apps = [
        {**app, "_region": region}
        for region, d in all_data.items()
        for app in d["applications"]
    ]
    if all_apps:
        t = Table(title=f"Applications ({total_apps} total)")
        t.add_column("Name", style="cyan")
        t.add_column("Environments", justify="right")
        t.add_column("Versions", justify="right")
        t.add_column("Created", style="dim")
        t.add_column("Region")

        for app in all_apps:
            created = app.get("DateCreated")
            created_str = created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else str(created or "")
            t.add_row(
                app.get("ApplicationName", ""),
                str(len(app.get("Environments", []))),
                str(len(app.get("Versions", []))),
                created_str,
                app.get("_region", ""),
            )
        console.print(t)

    # Versions table (condensed — top 50 newest)
    all_versions = [
        {**v, "_region": region}
        for region, d in all_data.items()
        for v in d["versions"]
    ]
    if all_versions:
        all_versions_sorted = sorted(
            all_versions,
            key=lambda v: v.get("DateCreated") or "",
            reverse=True,
        )
        display_versions = all_versions_sorted[:50]

        t = Table(title=f"Application Versions ({total_vers} total, showing {len(display_versions)})")
        t.add_column("Label", style="cyan")
        t.add_column("Application")
        t.add_column("Status")
        t.add_column("Created", style="dim")
        t.add_column("Region")

        for v in display_versions:
            created = v.get("DateCreated")
            created_str = created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else str(created or "")
            t.add_row(
                v.get("VersionLabel", ""),
                v.get("ApplicationName", ""),
                v.get("Status", ""),
                created_str,
                v.get("_region", ""),
            )
        console.print(t)
        if total_vers > 50:
            console.print(f"[dim]Showing 50 of {total_vers} versions. Full data saved in session.[/dim]")

    console.print(
        "[green]Elastic Beanstalk enumeration complete. "
        "Data saved under 'elasticbeanstalk' in session.[/green]"
    )
