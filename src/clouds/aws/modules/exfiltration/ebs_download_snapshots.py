import os
import subprocess
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def _get_cached_snapshots(session_mgr: AWSSessionManager) -> List[Dict[str, Any]]:
    """
    Recupera la lista di snapshot EBS già enumerati e salvati in 'ebs_snapshots'.
    """
    session_name = session_mgr.current_session
    if not session_name:
        return []

    return (
        session_mgr.enumerated_data.get(session_name, {}).get("ebs_snapshots", [])
        if session_name in session_mgr.enumerated_data
        else []
    )


def _pick_snapshot_interactive(snapshots: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Mostra una tabella di snapshot e chiede uno SnapshotId da scaricare.
    """
    if not snapshots:
        console.print("[yellow]No cached EBS snapshots in this session. Run 'enumerate_ebs_snapshots' first.[/yellow]")
        return None

    # Small reference table
    table = Table(title="Cached EBS Snapshots (from 'ebs_snapshots')")
    table.add_column("SnapshotId", style="cyan")
    table.add_column("Region")
    table.add_column("Encrypted")
    table.add_column("SizeGiB")
    table.add_column("VolumeId")

    max_rows = 50
    for s in snapshots[:max_rows]:
        table.add_row(
            s.get("SnapshotId", ""),
            s.get("Region", ""),
            "✅" if s.get("Encrypted") else "❌",
            str(s.get("VolumeSizeGiB") or ""),
            s.get("VolumeId", ""),
        )

    console.print(table)
    if len(snapshots) > max_rows:
        console.print(f"[dim]Showing first {max_rows} snapshots out of {len(snapshots)} cached.[/dim]")

    snapshot_id = Prompt.ask("[cyan]SnapshotId to download[/cyan]")
    snapshot = next((s for s in snapshots if s.get("SnapshotId") == snapshot_id), None)
    if not snapshot:
        console.print(f"[red]SnapshotId '{snapshot_id}' not found in cached 'ebs_snapshots'.[/red]")
        return None

    return snapshot


def _ensure_dsnap_installed() -> bool:
    """
    Verifica che 'dsnap' sia disponibile nel PATH.
    """
    try:
        subprocess.run(
            ["dsnap", "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return True
    except FileNotFoundError:
        console.print(
            "[red]'dsnap' not found in PATH.[/red] "
            "Install it from https://github.com/RhinoSecurityLabs/dsnap before using this module."
        )
        return False


def download_ebs_snapshot(session_mgr: AWSSessionManager, snapshot_id: Optional[str] = None, out_dir: Optional[str] = None) -> None:
    """
    Download an EBS snapshot as a local disk image using the 'dsnap' tool.

    - Uses snapshots cached in 'ebs_snapshots' (from enumerate_ebs_snapshots).
    - Requires 'dsnap' installed and configured with appropriate AWS credentials.
    - By default downloads to the current working directory, or to 'out_dir' if provided.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys' or use an assumed-role session.[/red]")
        return

    if not _ensure_dsnap_installed():
        return

    snapshots = _get_cached_snapshots(session_mgr)
    if not snapshots:
        console.print(
            "[yellow]No EBS snapshots cached in this session. "
            "Run 'enumerate_ebs_snapshots' first.[/yellow]"
        )
        return

    chosen_snapshot: Optional[Dict[str, Any]] = None

    if snapshot_id:
        chosen_snapshot = next((s for s in snapshots if s.get("SnapshotId") == snapshot_id), None)
        if not chosen_snapshot:
            console.print(
                f"[red]SnapshotId '{snapshot_id}' not found in cached 'ebs_snapshots'.[/red]"
            )
            return
    else:
        chosen_snapshot = _pick_snapshot_interactive(snapshots)
        if not chosen_snapshot:
            return

    snap_id = chosen_snapshot["SnapshotId"]
    region = chosen_snapshot.get("Region") or session_mgr.current_session_data.get("region")

    if not region:
        console.print("[red]Unable to determine region for the selected snapshot.[/red]")
        return

    if not out_dir:
        out_dir = os.getcwd()
    else:
        os.makedirs(out_dir, exist_ok=True)

    console.print(
        f"[bold blue]💾 Downloading snapshot {snap_id} from region {region} using dsnap...[/bold blue]"
    )
    console.print(f"[dim]Output directory: {out_dir}[/dim]")

    # Costruiamo il comando dsnap.
    # dsnap --region <region> get <snapshot-id>
    # (dsnap will use the same credentials from the current profile/ENV)
    cmd = [
        "dsnap",
        "--region",
        region,
        "get",
        snap_id,
    ]

    try:
        subprocess.run(cmd, cwd=out_dir, check=True)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]dsnap failed with exit code {e.returncode}.[/red]")
        return
    except Exception as e:
        console.print(f"[red]Failed to run dsnap: {str(e)}[/red]")
        return

    # dsnap saves to <cwd>/<snapshot-id>.img by default
    output_path = os.path.join(out_dir, f"{snap_id}.img")
    if os.path.exists(output_path):
        console.print(
            f"[green]Snapshot image downloaded successfully:[/green] {output_path}"
        )
    else:
        console.print(
            "[yellow]dsnap completed, but the expected output file "
            f"'{output_path}' was not found. Check dsnap logs/output.[/yellow]"
        )
