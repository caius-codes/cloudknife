import base64
import gzip
import re
from typing import Any, Dict, List

from botocore.exceptions import ClientError
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory

console = Console()

# Patterns that may indicate sensitive data in UserData (case-insensitive)
_SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(secret[_\-]?(?:key|access)?|api[_\-]?key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(token|bearer)\s*[=:]\s*\S+'),
    re.compile(r'(?i)aws[_\-]?(?:access[_\-]?key|secret[_\-]?access)[_\-]?(?:id)?\s*[=:]\s*\S+'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'(?i)(db[_\-]?pass(?:word)?|database[_\-]?pass|mysql[_\-]?pass|pg[_\-]?pass)\s*[=:]\s*\S+'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'(?i)(private[_\-]?key|rsa[_\-]?key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(credential|cred)\s*[=:]\s*\S+'),
]


def _decode_userdata(raw: str) -> str:
    """Decode base64 UserData, transparently decompressing gzip if needed."""
    try:
        decoded = base64.b64decode(raw)
        try:
            return gzip.decompress(decoded).decode("utf-8", errors="replace")
        except (OSError, Exception):
            return decoded.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[decode error: {e}]"


def _scan_secrets(text: str) -> List[str]:
    """Return a deduplicated list of suspicious pattern matches found in text."""
    hits = []
    seen = set()
    for pattern in _SECRET_PATTERNS:
        for match in pattern.findall(text):
            hit = match if isinstance(match, str) else str(match)
            # No truncation - show full pattern match
            if hit not in seen:
                seen.add(hit)
                hits.append(hit)
    return hits


def _syntax_highlight(content: str) -> Syntax:
    """Pick a syntax lexer based on content heuristics."""
    stripped = content.strip()
    if stripped.startswith(("#!/", "#cloud")):
        lang = "bash"
    elif stripped.startswith(("<?xml", "<!D", "<")):
        lang = "xml"
    elif stripped.startswith(("{", "[")):
        lang = "json"
    else:
        lang = "bash"  # most UserData is shell-ish
    return Syntax(content, lang, theme="monokai", line_numbers=True)


def enumerate_launch_templates(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate EC2 Launch Templates across configured regions.

    For each template fetches the $Latest version data and decodes UserData
    (base64 + optional gzip). Scans decoded content for patterns that may
    indicate secrets: passwords, tokens, API keys, AWS key IDs, private keys.

    Results saved under 'launch_templates' in session enumeration data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="EC2 Launch Templates")
    client_factory = RegionalClientFactory(session_mgr)

    console.print(
        f"[bold blue]🚀 Enumerating EC2 Launch Templates in {len(regions)} region(s)[/bold blue]"
    )

    all_templates: List[Dict[str, Any]] = []

    for region in regions:
        ec2 = client_factory.get_client("ec2", region)

        templates_in_region: List[Dict] = []
        try:
            paginator = ec2.get_paginator("describe_launch_templates")
            for page in paginator.paginate():
                templates_in_region.extend(page.get("LaunchTemplates", []))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                console.print(f"[dim]  {region}: access denied[/dim]")
            else:
                console.print(f"[dim]  {region}: {code}[/dim]")
            continue
        except Exception as e:
            console.print(f"[dim]  {region}: {str(e)[:80]}[/dim]")
            continue

        if not templates_in_region:
            continue

        console.print(f"[cyan]→ {region}: {len(templates_in_region)} template(s)[/cyan]")

        for tmpl in templates_in_region:
            lt_id = tmpl.get("LaunchTemplateId", "")
            lt_name = tmpl.get("LaunchTemplateName", "")

            # Fetch ALL versions for this template
            all_versions = []
            try:
                resp = ec2.describe_launch_template_versions(
                    LaunchTemplateId=lt_id,
                )
                all_versions = resp.get("LaunchTemplateVersions", [])
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                console.print(f"[dim]  Error fetching versions for {lt_name}: {code}[/dim]")

            # Process each version
            versions_with_data = []
            for ver in all_versions:
                version_num = ver.get("VersionNumber", 0)
                version_data = ver.get("LaunchTemplateData", {})
                userdata_raw = version_data.get("UserData", "")

                userdata_decoded = ""
                userdata_hints = []
                if userdata_raw:
                    userdata_decoded = _decode_userdata(userdata_raw)
                    userdata_hints = _scan_secrets(userdata_decoded)

                versions_with_data.append({
                    "VersionNumber": version_num,
                    "HasUserData": bool(userdata_raw),
                    "UserDataDecoded": userdata_decoded,
                    "UserDataHints": userdata_hints,
                    "LaunchTemplateData": version_data,
                })

            all_templates.append({
                "Region": region,
                "LaunchTemplateId": lt_id,
                "LaunchTemplateName": lt_name,
                "LatestVersionNumber": tmpl.get("LatestVersionNumber", 1),
                "DefaultVersionNumber": tmpl.get("DefaultVersionNumber", 1),
                "TotalVersions": len(all_versions),
                "Versions": versions_with_data,
            })

    # ── Persist ─────────────────────────────────────────────────────────────────
    session_mgr.save_enumeration_data("launch_templates", all_templates)

    if not all_templates:
        console.print("[yellow]No launch templates found in any configured region.[/yellow]")
        return

    # ── Summary table ────────────────────────────────────────────────────────────
    t = Table(title=f"EC2 Launch Templates ({len(all_templates)} total)")
    t.add_column("Name", style="cyan")
    t.add_column("ID", style="dim")
    t.add_column("Versions", justify="right")
    t.add_column("With UserData", justify="right")
    t.add_column("Secret hits")
    t.add_column("Region")

    for entry in all_templates:
        # Count versions with UserData and total secret hints
        versions_with_ud = [v for v in entry["Versions"] if v["HasUserData"]]
        total_hints = sum(len(v["UserDataHints"]) for v in versions_with_ud)

        if total_hints > 0:
            ud_cell = f"[bold red]{len(versions_with_ud)} ⚠[/bold red]"
            hints_cell = f"[red]{total_hints} match(es)[/red]"
        elif versions_with_ud:
            ud_cell = f"[yellow]{len(versions_with_ud)}[/yellow]"
            hints_cell = ""
        else:
            ud_cell = "[dim]0[/dim]"
            hints_cell = ""

        t.add_row(
            entry["LaunchTemplateName"],
            entry["LaunchTemplateId"],
            str(entry["TotalVersions"]),
            ud_cell,
            hints_cell,
            entry["Region"],
        )

    console.print(t)

    # ── UserData content for all versions ───────────────────────────────────────
    # Collect all template+version combinations that have UserData
    versions_to_display = []
    for entry in all_templates:
        for version in entry["Versions"]:
            if version["HasUserData"]:
                versions_to_display.append({
                    "template_name": entry["LaunchTemplateName"],
                    "template_id": entry["LaunchTemplateId"],
                    "region": entry["Region"],
                    "version_number": version["VersionNumber"],
                    "userdata_decoded": version["UserDataDecoded"],
                    "userdata_hints": version["UserDataHints"],
                })

    if not versions_to_display:
        console.print("[dim]No template versions with UserData found.[/dim]")
    else:
        console.print(
            f"\n[bold yellow]UserData content for {len(versions_to_display)} version(s) across all templates:[/bold yellow]"
        )

        for item in versions_to_display:
            console.print(
                f"\n[bold]── {item['template_name']} (v{item['version_number']}) "
                f"[{item['template_id']}] [{item['region']}] ──[/bold]"
            )

            if item["userdata_hints"]:
                console.print(
                    f"[bold red]⚠  {len(item['userdata_hints'])} potential secret pattern(s) detected:[/bold red]"
                )
                for hit in item["userdata_hints"]:
                    console.print(f"  [red]→ {hit}[/red]")
                console.print()

            # Print full content without truncation
            userdata_content = item["userdata_decoded"]
            console.print(_syntax_highlight(userdata_content))

            # Show character count to verify no truncation
            console.print(f"[dim]({len(userdata_content)} characters total)[/dim]")

    console.print(
        "\n[green]Data saved under 'launch_templates' in session.[/green]"
    )
