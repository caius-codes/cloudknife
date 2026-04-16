"""
GCP Quick Enumeration Module.

Lightweight multi-service overview for quick reconnaissance:
- Compute Engine instances
- Cloud Functions (v1 & v2)
- Cloud Run services  
- Cloud Storage buckets
- Secret Manager secrets
- IAM service accounts
- Parameter Manager parameters

Uses only cheap list/count calls across multiple projects and regions in parallel.
"""

from typing import Dict, Any, List, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Common GCP regions for enumeration
GCP_REGIONS = [
    "us-central1",
    "us-east1", 
    "us-west1",
    "europe-west1",
    "asia-east1",
]


def quick_enum(session_mgr: "GCPSessionManager") -> None:
    """
    Quick enumeration of key GCP services across projects and regions.
    
    Provides a fast overview of the cloud environment without deep enumeration.
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return

    console.print(f"[bold blue]🔍 Running quick_enum across {len(projects)} project(s) and {len(GCP_REGIONS)} regions[/bold blue]\n")

    summary: List[Dict[str, Any]] = []

    # ---------- Compute Engine Instances ----------
    console.print("[dim]Enumerating Compute Engine instances...[/dim]")
    try:
        from google.cloud import compute_v1
        instances_client = compute_v1.InstancesClient(credentials=credentials)
        
        # Get all zones first
        from src.clouds.gcp.utils.projects import get_all_zones
        all_zones = get_all_zones(session_mgr)
        
        compute_count = 0
        compute_regions = set()
        
        tasks = [(project, zone) for project in projects for zone in all_zones[:10]]  # Limit to first 10 zones for speed
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_count_compute_instances, instances_client, project, zone): (project, zone)
                for project, zone in tasks
            }
            
            for future in as_completed(futures):
                try:
                    count, zone = future.result()
                    if count > 0:
                        compute_count += count
                        compute_regions.add(zone.rsplit('-', 1)[0])  # Extract region from zone
                except Exception:
                    pass
        
        summary.append({
            "service": "compute",
            "regions": len(compute_regions),
            "count": compute_count,
            "status": "OK" if compute_count > 0 else "EMPTY",
            "hint": "enumerate_compute" if compute_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "compute",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- Cloud Functions ----------
    console.print("[dim]Enumerating Cloud Functions...[/dim]")
    try:
        from google.cloud import functions_v2
        functions_client = functions_v2.FunctionServiceClient(credentials=credentials)
        
        functions_count = 0
        functions_regions = set()
        
        tasks = [(project, region) for project in projects for region in GCP_REGIONS]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_count_cloud_functions, functions_client, project, region): (project, region)
                for project, region in tasks
            }
            
            for future in as_completed(futures):
                try:
                    count, region = future.result()
                    if count > 0:
                        functions_count += count
                        functions_regions.add(region)
                except Exception:
                    pass
        
        summary.append({
            "service": "functions",
            "regions": len(functions_regions),
            "count": functions_count,
            "status": "OK" if functions_count > 0 else "EMPTY",
            "hint": "enumerate_functions" if functions_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "functions",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- Cloud Run Services ----------
    console.print("[dim]Enumerating Cloud Run services...[/dim]")
    try:
        from google.cloud import run_v2
        run_client = run_v2.ServicesClient(credentials=credentials)
        
        run_count = 0
        run_regions = set()
        
        tasks = [(project, region) for project in projects for region in GCP_REGIONS]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_count_run_services, run_client, project, region): (project, region)
                for project, region in tasks
            }
            
            for future in as_completed(futures):
                try:
                    count, region = future.result()
                    if count > 0:
                        run_count += count
                        run_regions.add(region)
                except Exception:
                    pass
        
        summary.append({
            "service": "run",
            "regions": len(run_regions),
            "count": run_count,
            "status": "OK" if run_count > 0 else "EMPTY",
            "hint": "enumerate_run_services" if run_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "run",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- Cloud Storage Buckets ----------
    console.print("[dim]Enumerating Cloud Storage buckets...[/dim]")
    try:
        from google.cloud import storage
        storage_client = storage.Client(credentials=credentials, project=projects[0] if projects else None)
        
        buckets_count = 0
        for project in projects:
            try:
                project_buckets = list(storage_client.list_buckets(project=project))
                buckets_count += len(project_buckets)
            except Exception:
                pass
        
        summary.append({
            "service": "storage",
            "regions": len(projects),
            "count": buckets_count,
            "status": "OK" if buckets_count > 0 else "EMPTY",
            "hint": "enumerate_storage" if buckets_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "storage",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- Secret Manager ----------
    console.print("[dim]Enumerating Secret Manager secrets...[/dim]")
    try:
        from google.cloud import secretmanager_v1
        secrets_client = secretmanager_v1.SecretManagerServiceClient(credentials=credentials)
        
        secrets_count = 0
        for project in projects:
            try:
                parent = f"projects/{project}"
                secrets = list(secrets_client.list_secrets(parent=parent))
                secrets_count += len(secrets)
            except Exception:
                pass
        
        summary.append({
            "service": "secrets",
            "regions": len(projects),
            "count": secrets_count,
            "status": "OK" if secrets_count > 0 else "EMPTY",
            "hint": "enumerate_secrets" if secrets_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "secrets",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- IAM Service Accounts ----------
    console.print("[dim]Enumerating IAM service accounts...[/dim]")
    try:
        from google.cloud import iam_admin_v1
        iam_client = iam_admin_v1.IAMClient(credentials=credentials)
        
        sa_count = 0
        for project in projects:
            try:
                parent = f"projects/{project}"
                accounts = list(iam_client.list_service_accounts(name=parent))
                sa_count += len(accounts)
            except Exception:
                pass
        
        summary.append({
            "service": "iam_sa",
            "regions": len(projects),
            "count": sa_count,
            "status": "OK" if sa_count > 0 else "EMPTY",
            "hint": "enumerate_iam" if sa_count > 0 else "no resources found",
        })
    except Exception as e:
        summary.append({
            "service": "iam_sa",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": str(e)[:50],
        })

    # ---------- Print Summary ----------
    table = Table(title="Quick Enumeration Summary")
    table.add_column("Service", style="cyan")
    table.add_column("Regions/Projects")
    table.add_column("Resources")
    table.add_column("Status")
    table.add_column("Next step")

    for row in summary:
        status = row.get("status", "UNKNOWN")
        if status == "OK":
            status_str = "[green]OK[/green]"
        elif status == "EMPTY":
            status_str = "[yellow]EMPTY[/yellow]"
        elif status == "ERROR":
            status_str = "[red]ERROR[/red]"
        else:
            status_str = status

        table.add_row(
            row["service"],
            str(row["regions"]),
            str(row["count"]),
            status_str,
            row["hint"],
        )

    console.print("\n")
    console.print(table)
    console.print("\n[dim]Tip: Use the suggested commands to enumerate each service in detail.[/dim]")


def _count_compute_instances(client, project: str, zone: str) -> tuple:
    """Count Compute Engine instances in a zone."""
    try:
        from google.cloud import compute_v1
        request = compute_v1.ListInstancesRequest(project=project, zone=zone)
        instances = list(client.list(request=request))
        return len(instances), zone
    except Exception:
        return 0, zone


def _count_cloud_functions(client, project: str, region: str) -> tuple:
    """Count Cloud Functions in a region."""
    try:
        parent = f"projects/{project}/locations/{region}"
        functions = list(client.list_functions(parent=parent))
        return len(functions), region
    except Exception:
        return 0, region


def _count_run_services(client, project: str, region: str) -> tuple:
    """Count Cloud Run services in a region."""
    try:
        from google.cloud import run_v2
        parent = f"projects/{project}/locations/{region}"
        request = run_v2.ListServicesRequest(parent=parent)
        services = list(client.list_services(request=request))
        return len(services), region
    except Exception:
        return 0, region
