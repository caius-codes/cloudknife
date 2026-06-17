"""
GCP IAM Permission Bruteforce Module.

Uses a HYBRID approach:
1. testIamPermissions API (fast, quiet) - tests permissions at project level
2. Actual API calls (like AWS) - verifies real access, catches resource-level permissions

This is necessary because testIamPermissions on projects doesn't catch:
- Permissions granted at resource level (e.g., on specific service accounts)
- Inherited permissions from org/folder
- Some permission types that aren't testable via this API

Usage:
    enumerate_bruteforce_permissions            # Fast mode (default) - high-value permissions
    enumerate_bruteforce_permissions full       # Full mode - extended common services
    enumerate_bruteforce_permissions low        # Low mode - comprehensive but less exploitable
    enumerate_bruteforce_permissions iam,compute fast  # Filter specific services
"""

from typing import Dict, List, Any, Optional, Tuple, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

from src.data.gcp_iam_permissions import (
    get_gcp_profile_permissions,
    is_dangerous_permission,
)

console = Console()


# Maximum permissions per testIamPermissions call (GCP limit is 100)
MAX_PERMISSIONS_PER_CALL = 100


# =============================================================================
# API Call Mappings - Maps permissions to actual API calls for verification
# Format: "permission_name": ("client_module", "client_class", "method", {params})
# =============================================================================

# Permissions that can be verified via actual API calls
API_CALL_MAPPING: Dict[str, Tuple[str, str, str, Dict[str, Any]]] = {
    # IAM Service Accounts
    "iam.serviceAccounts.list": (
        "google.cloud.iam_admin_v1",
        "IAMClient",
        "list_service_accounts",
        {"name": "projects/{project_id}"},
    ),
    "iam.roles.list": (
        "google.cloud.iam_admin_v1",
        "IAMClient",
        "list_roles",
        {"parent": "projects/{project_id}"},
    ),

    # Resource Manager
    "resourcemanager.projects.get": (
        "google.cloud.resourcemanager_v3",
        "ProjectsClient",
        "get_project",
        {"name": "projects/{project_id}"},
    ),
    "resourcemanager.projects.getIamPolicy": (
        "google.cloud.resourcemanager_v3",
        "ProjectsClient",
        "get_iam_policy",
        {"resource": "projects/{project_id}"},
    ),

    # Compute Engine
    "compute.instances.list": (
        "google.cloud.compute_v1",
        "InstancesClient",
        "aggregated_list",
        {"project": "{project_id}"},
    ),
    "compute.disks.list": (
        "google.cloud.compute_v1",
        "DisksClient",
        "aggregated_list",
        {"project": "{project_id}"},
    ),
    "compute.firewalls.list": (
        "google.cloud.compute_v1",
        "FirewallsClient",
        "list",
        {"project": "{project_id}"},
    ),
    "compute.networks.list": (
        "google.cloud.compute_v1",
        "NetworksClient",
        "list",
        {"project": "{project_id}"},
    ),

    # Cloud Storage
    "storage.buckets.list": (
        "google.cloud.storage",
        "Client",
        "list_buckets",
        {},  # Uses project from credentials
    ),

    # Secret Manager
    "secretmanager.secrets.list": (
        "google.cloud.secretmanager_v1",
        "SecretManagerServiceClient",
        "list_secrets",
        {"parent": "projects/{project_id}"},
    ),

    # Cloud Functions
    "cloudfunctions.functions.list": (
        "google.cloud.functions_v2",
        "FunctionServiceClient",
        "list_functions",
        {"parent": "projects/{project_id}/locations/-"},
    ),

    # Cloud Run
    "run.services.list": (
        "google.cloud.run_v2",
        "ServicesClient",
        "list_services",
        {"parent": "projects/{project_id}/locations/-"},
    ),

    # BigQuery
    "bigquery.datasets.list": (
        "google.cloud.bigquery",
        "Client",
        "list_datasets",
        {},  # Uses project from client
    ),

    # Pub/Sub
    "pubsub.topics.list": (
        "google.cloud.pubsub_v1",
        "PublisherClient",
        "list_topics",
        {"project": "projects/{project_id}"},
    ),
    "pubsub.subscriptions.list": (
        "google.cloud.pubsub_v1",
        "SubscriberClient",
        "list_subscriptions",
        {"project": "projects/{project_id}"},
    ),

    # Cloud SQL
    "cloudsql.instances.list": (
        "googleapiclient.discovery",
        "build",
        "instances.list",
        {"project": "{project_id}"},
    ),

    # GKE
    "container.clusters.list": (
        "google.cloud.container_v1",
        "ClusterManagerClient",
        "list_clusters",
        {"parent": "projects/{project_id}/locations/-"},
    ),

    # Logging
    "logging.logs.list": (
        "google.cloud.logging_v2",
        "LoggingServiceV2Client",
        "list_logs",
        {"parent": "projects/{project_id}"},
    ),

    # KMS
    "cloudkms.keyRings.list": (
        "google.cloud.kms_v1",
        "KeyManagementServiceClient",
        "list_key_rings",
        {"parent": "projects/{project_id}/locations/global"},
    ),
}


def _chunk_list(lst: List[str], chunk_size: int) -> List[List[str]]:
    """Split a list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def _test_permissions_on_project(
    session_mgr: "GCPSessionManager",
    project_id: str,
    permissions: List[str],
) -> List[str]:
    """
    Test a list of permissions against a project using testIamPermissions API.

    Always uses REST API v1 for consistency with gcp-iam-brute tool behavior.
    Falls back to client library v3 only if REST API fails completely.
    """
    auth_method = session_mgr.current_session_data.get("auth_method")

    # For access_token, just use REST API directly (no credentials check needed)
    if auth_method == "access_token":
        token = session_mgr.current_session_data.get("access_token")
        if not token:
            console.print("[red]No access token found in session[/red]")
            return []
        return _test_permissions_rest_api(session_mgr, project_id, permissions)

    # For service account/ADC, check credentials
    credentials = session_mgr.get_credentials()
    if not credentials:
        return []

    # Try REST API first (preferred for consistency)
    result = _test_permissions_rest_api(session_mgr, project_id, permissions)
    if result:
        return result

    # Fallback to client library for service account/ADC if REST failed
    console.print("[dim]Falling back to client library...[/dim]")
    return _test_permissions_client_lib(session_mgr, project_id, permissions, credentials)


def _test_permissions_rest_api(
    session_mgr: "GCPSessionManager",
    project_id: str,
    permissions: List[str],
) -> List[str]:
    """
    Test permissions using direct REST API call.

    Uses v1 API like gcp-iam-brute for better compatibility.
    Reads token directly from session data (not from credentials cache).

    Implements divide-and-conquer for 400 errors: when a batch contains
    invalid permissions, split and retry to find valid ones.
    """
    import requests

    # IMPORTANT: Read token directly from session data like test_token does
    # This avoids any credentials caching issues
    auth_method = session_mgr.current_session_data.get("auth_method")
    token = session_mgr.current_session_data.get("access_token")

    # For service account/ADC, try to get token from credentials
    if not token and auth_method in ("service_account", "adc"):
        from google.auth.transport.requests import Request
        credentials = session_mgr.get_credentials()
        if credentials:
            try:
                if hasattr(credentials, "refresh"):
                    credentials.refresh(Request())
                if hasattr(credentials, "token"):
                    token = credentials.token
            except Exception as e:
                console.print(f"[dim]Could not refresh credentials: {e}[/dim]")

    if not token:
        console.print("[dim]No access token available for REST API[/dim]")
        return []

    # Debug: show token info
    console.print(f"[dim]Using token: {token[:30]}... ({len(token)} chars)[/dim]")

    # Use v1 API like gcp-iam-brute (v3 has different behavior for some permissions)
    api_base = "https://cloudresourcemanager.googleapis.com/v1"
    url = f"{api_base}/projects/{project_id}:testIamPermissions"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    def test_batch(perms: List[str], depth: int = 0) -> List[str]:
        """
        Test a batch of permissions, using divide-and-conquer on 400 errors.

        When the API returns 400 (invalid permission in batch), we split the
        batch in half and retry each half recursively.
        """
        if not perms:
            return []

        indent = "  " * depth

        try:
            body = {"permissions": perms}
            response = requests.post(url, json=body, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                granted = result.get("permissions", [])
                if depth == 0:
                    console.print(f"[dim]{indent}Batch of {len(perms)} → {len(granted)} granted[/dim]")
                return granted

            elif response.status_code == 400:
                # Invalid permission in batch - split and retry
                if len(perms) == 1:
                    # Single invalid permission - skip it
                    if depth == 0:
                        console.print(f"[dim]{indent}Skipping invalid: {perms[0]}[/dim]")
                    return []

                # Split in half and retry each half
                mid = len(perms) // 2
                left_half = perms[:mid]
                right_half = perms[mid:]

                if depth == 0:
                    console.print(f"[dim]{indent}Batch of {len(perms)} has invalid perms, splitting...[/dim]")

                left_results = test_batch(left_half, depth + 1)
                right_results = test_batch(right_half, depth + 1)
                return left_results + right_results

            elif response.status_code == 403:
                # Permission denied to test - continue
                if depth == 0:
                    console.print(f"[dim]{indent}403 Forbidden for batch[/dim]")
                return []

            elif response.status_code == 401:
                console.print("[yellow]Access token may be expired or invalid[/yellow]")
                return []

            else:
                if depth == 0:
                    console.print(f"[dim]{indent}API error ({response.status_code})[/dim]")
                return []

        except requests.RequestException as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return []

    # Process permissions in chunks, using divide-and-conquer for each chunk
    all_granted = []
    chunks = _chunk_list(permissions, MAX_PERMISSIONS_PER_CALL)

    for i, chunk in enumerate(chunks):
        console.print(f"[dim]Testing chunk {i+1}/{len(chunks)} ({len(chunk)} permissions)...[/dim]")
        granted = test_batch(chunk)
        all_granted.extend(granted)

    console.print(f"[dim]Total granted from REST API: {len(all_granted)}[/dim]")
    return all_granted


def _test_permissions_client_lib(
    session_mgr: "GCPSessionManager",
    project_id: str,
    permissions: List[str],
    credentials,
) -> List[str]:
    """
    Test permissions using Google Cloud client library.

    Better for service account and ADC auth methods.
    """
    from google.cloud import resourcemanager_v3
    from google.api_core.exceptions import GoogleAPICallError, PermissionDenied

    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        all_granted = []

        for chunk in _chunk_list(permissions, MAX_PERMISSIONS_PER_CALL):
            try:
                response = client.test_iam_permissions(
                    resource=f"projects/{project_id}",
                    permissions=chunk,
                )
                all_granted.extend(response.permissions)
            except PermissionDenied:
                continue
            except GoogleAPICallError as e:
                console.print(f"[dim]API error testing permissions: {e}[/dim]")
                continue

        return all_granted

    except Exception as e:
        console.print(f"[dim]testIamPermissions error: {e}[/dim]")
        return []


def _test_api_call(
    session_mgr: "GCPSessionManager",
    project_id: str,
    permission: str,
) -> Tuple[str, str, str]:
    """
    Test a permission by making an actual API call.

    Returns:
        Tuple of (permission, status, error_message)
        status: "ALLOWED", "DENIED", "SKIPPED", "ERROR"
    """
    if permission not in API_CALL_MAPPING:
        return (permission, "SKIPPED", "No API mapping")

    module_name, class_name, method_name, params_template = API_CALL_MAPPING[permission]

    # Format params with project_id
    params = {}
    for key, value in params_template.items():
        if isinstance(value, str):
            params[key] = value.format(project_id=project_id)
        else:
            params[key] = value

    credentials = session_mgr.get_credentials()
    if not credentials:
        return (permission, "ERROR", "No credentials")

    try:
        # Special handling for different client types
        if module_name == "google.cloud.storage":
            from google.cloud import storage
            client = storage.Client(credentials=credentials, project=project_id)
            method = getattr(client, method_name)
            # Just try to iterate once
            result = method()
            next(iter(result), None)
            return (permission, "ALLOWED", "")

        elif module_name == "google.cloud.bigquery":
            from google.cloud import bigquery
            client = bigquery.Client(credentials=credentials, project=project_id)
            method = getattr(client, method_name)
            result = method()
            next(iter(result), None)
            return (permission, "ALLOWED", "")

        elif module_name == "googleapiclient.discovery":
            # For Cloud SQL which uses discovery API
            from googleapiclient import discovery
            from google.auth.transport.requests import Request

            # Refresh credentials if needed
            if hasattr(credentials, 'refresh'):
                try:
                    credentials.refresh(Request())
                except Exception:
                    pass

            service = discovery.build('sqladmin', 'v1', credentials=credentials)
            # Parse method path like "instances.list"
            parts = method_name.split('.')
            obj = service
            for part in parts:
                obj = getattr(obj, part)
            result = obj(**params).execute()
            return (permission, "ALLOWED", "")

        else:
            # Standard Google Cloud client
            import importlib
            module = importlib.import_module(module_name)
            client_class = getattr(module, class_name)
            client = client_class(credentials=credentials)
            method = getattr(client, method_name)

            # Call the method
            result = method(**params)

            # For paginated results, try to get first item
            if hasattr(result, '__iter__') and not isinstance(result, (str, bytes, dict)):
                next(iter(result), None)

            return (permission, "ALLOWED", "")

    except Exception as e:
        error_str = str(e).lower()

        # Check for permission denied errors
        if any(x in error_str for x in [
            "permission denied",
            "403",
            "access denied",
            "forbidden",
            "unauthorized",
            "does not have",
            "caller does not have permission",
        ]):
            return (permission, "DENIED", str(e)[:100])

        # Check for "not found" which usually means we have permission but resource doesn't exist
        if any(x in error_str for x in [
            "not found",
            "404",
            "does not exist",
            "no such",
        ]):
            return (permission, "ALLOWED", "Resource not found (permission OK)")

        # Check for "not enabled" (API not enabled, but we might have permission)
        if any(x in error_str for x in [
            "not enabled",
            "api not enabled",
            "service not enabled",
            "has not been used",
        ]):
            return (permission, "UNKNOWN", "API not enabled")

        # Other errors - assume denied for safety
        return (permission, "DENIED", str(e)[:100])


def _normalize_services_arg(
    services_arg: Optional[str],
    available_services: List[str],
) -> List[str]:
    """Parse service filter argument."""
    if not services_arg:
        return available_services

    requested = [s.strip().lower() for s in services_arg.split(",") if s.strip()]
    valid = [s for s in requested if s in available_services]

    for s in requested:
        if s not in available_services:
            console.print(f"[yellow]Service '{s}' not available in this profile.[/yellow]")

    if not valid:
        console.print("[red]No valid services selected. Aborting.[/red]")

    return valid


def enumerate_bruteforce_permissions(
    session_mgr: "GCPSessionManager",
    services_arg: Optional[str] = None,
    mode: str = "fast",
) -> Optional[Dict[str, Any]]:
    """
    Enumerate GCP IAM permissions using bruteforce hybrid approach:
    1. testIamPermissions API (fast, project-level)
    2. Actual API calls (slower, but catches resource-level permissions)
    """
    # Validate credentials - check differently based on auth method
    auth_method = session_mgr.current_session_data.get("auth_method")
    if auth_method == "access_token":
        # For access_token, just check if token exists (don't use get_credentials)
        if not session_mgr.current_session_data.get("access_token"):
            console.print("[red]No access token found. Use 'set_token' to configure.[/red]")
            return None
    else:
        # For service account/ADC, use get_credentials
        if not session_mgr.get_credentials():
            console.print("[red]No credentials configured. Use 'set_credentials', 'set_adc', or 'set_token'.[/red]")
            return None

    # Get project
    project_id = session_mgr.default_project
    if not project_id:
        console.print("[bold yellow]🔍 GCP IAM Permission Enumeration[/bold yellow]")
        project_id = Prompt.ask("[cyan]Project ID[/cyan]", default="")
        if not project_id:
            console.print("[red]Project ID is required for permission enumeration.[/red]")
            return None

    # Validate mode
    mode = mode.lower()
    if mode not in ("fast", "full", "low"):
        console.print("[yellow]Unknown mode, falling back to 'fast'.[/yellow]")
        mode = "fast"

    # Get permissions for this mode
    profile_permissions = get_gcp_profile_permissions(mode)
    available_services = list(profile_permissions.keys())

    # Filter services
    target_services = _normalize_services_arg(services_arg, available_services)
    if not target_services:
        return None

    # Build permission list
    all_permissions: List[str] = []
    permission_to_service: Dict[str, str] = {}

    for service in target_services:
        perms = profile_permissions.get(service, [])
        for perm in perms:
            all_permissions.append(perm)
            permission_to_service[perm] = service

    total_permissions = len(all_permissions)

    console.print(f"\n[bold blue]🔍 GCP IAM Permission Bruteforce ({mode} mode)[/bold blue]")
    console.print(f"[dim]Project: {project_id}[/dim]")
    console.print(f"[dim]Services: {', '.join(target_services)}[/dim]")
    console.print(f"[dim]Total permissions to test: {total_permissions}[/dim]\n")

    # =========================================================================
    # Phase 1: testIamPermissions (fast, bulk)
    # =========================================================================
    console.print("[cyan]Phase 1: Testing via testIamPermissions API...[/cyan]")

    test_iam_granted = set(_test_permissions_on_project(
        session_mgr,
        project_id,
        all_permissions,
    ))

    console.print(f"[dim]  → testIamPermissions found: {len(test_iam_granted)} permissions[/dim]")

    # =========================================================================
    # Phase 2: Actual API calls for key permissions
    # =========================================================================
    console.print("[cyan]Phase 2: Verifying via actual API calls...[/cyan]")

    api_results: Dict[str, str] = {}  # permission -> status
    api_verified_granted: set = set()

    # Only test permissions that have API mappings
    testable_permissions = [p for p in all_permissions if p in API_CALL_MAPPING]

    if testable_permissions:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("{task.completed}/{task.total} permissions"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[cyan]Testing API calls...",
                total=len(testable_permissions)
            )

            for perm in testable_permissions:
                service = permission_to_service.get(perm, "unknown")
                progress.update(task, description=f"[cyan]Testing {perm}")

                permission, status, error = _test_api_call(session_mgr, project_id, perm)
                api_results[permission] = status

                if status == "ALLOWED":
                    api_verified_granted.add(permission)
                elif status == "DENIED":
                    pass  # Just count it
                else:
                    pass  # SKIPPED, ERROR, etc.

                progress.advance(task)

    console.print(f"[dim]  → API calls verified: {len(api_verified_granted)} permissions[/dim]")

    # =========================================================================
    # Merge results: combine testIamPermissions + API call results
    # =========================================================================
    # A permission is GRANTED if:
    # - testIamPermissions says yes, OR
    # - Actual API call succeeded
    current_run_granted = test_iam_granted | api_verified_granted

    # =========================================================================
    # Load existing results and MERGE (don't overwrite!)
    # =========================================================================
    existing_data = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("iam_bruteforce", {})

    # Get previously found permissions
    existing_granted = set(existing_data.get("all_granted", []))
    existing_test_iam = set(existing_data.get("test_iam_granted", []))
    existing_api_verified = set(existing_data.get("api_verified_granted", []))
    existing_dangerous = set(existing_data.get("dangerous_found", []))
    existing_modes = existing_data.get("modes_run", [])

    # Merge with current run
    all_granted = existing_granted | current_run_granted
    merged_test_iam = existing_test_iam | test_iam_granted
    merged_api_verified = existing_api_verified | api_verified_granted

    # Track which modes have been run
    modes_run = list(set(existing_modes + [mode]))

    # Count new permissions found in this run
    new_permissions_found = current_run_granted - existing_granted
    if new_permissions_found:
        console.print(f"\n[green]✨ Found {len(new_permissions_found)} NEW permission(s) in this run![/green]")
    elif existing_granted:
        console.print(f"\n[dim]No new permissions found (already have {len(existing_granted)} from previous runs)[/dim]")

    # Build final results per service (using ALL granted permissions)
    results: Dict[str, Dict[str, Any]] = {}
    dangerous_found: List[str] = []

    # Get all services from current + existing
    existing_services = set(existing_data.get("by_service", {}).keys())
    all_services = set(target_services) | existing_services

    for service in all_services:
        # Get permissions for this service from current profile
        perms_current = set(profile_permissions.get(service, []))

        # Get permissions from existing data for this service
        existing_svc_data = existing_data.get("by_service", {}).get(service, {})
        perms_existing = set(existing_svc_data.get("granted_permissions", []) +
                           existing_svc_data.get("denied_permissions", []))

        # All permissions we've tested for this service
        all_perms_tested = perms_current | perms_existing

        service_granted = []
        service_denied = []

        for perm in all_perms_tested:
            if perm in all_granted:
                service_granted.append(perm)
                if is_dangerous_permission(perm):
                    dangerous_found.append(perm)
            else:
                service_denied.append(perm)

        if service_granted or service_denied:  # Only include if we have data
            results[service] = {
                "total": len(all_perms_tested),
                "granted": len(service_granted),
                "denied": len(service_denied),
                "granted_permissions": service_granted,
                "denied_permissions": service_denied,
            }

    # Calculate totals across all runs
    total_tested_all = sum(r["total"] for r in results.values())

    # Save merged results
    enumeration_results = {
        "mode": mode,  # Last mode run
        "modes_run": modes_run,  # All modes that have been run
        "project_id": project_id,
        "services": list(all_services),
        "total_tested": total_tested_all,
        "total_granted": len(all_granted),
        "total_denied": total_tested_all - len(all_granted),
        "dangerous_found": list(set(dangerous_found)),
        "by_service": results,
        "all_granted": list(all_granted),
        "test_iam_granted": list(merged_test_iam),
        "api_verified_granted": list(merged_api_verified),
        "new_in_last_run": list(new_permissions_found),
    }

    session_mgr.save_enumeration_data("iam_bruteforce", enumeration_results)

    # =========================================================================
    # Display results
    # =========================================================================
    console.print()

    # Show modes run
    modes_str = ", ".join(modes_run)
    title = f"📊 Permission Summary (modes run: {modes_str})"

    summary_table = Table(title=title)
    summary_table.add_column("Service", style="cyan", no_wrap=True)
    summary_table.add_column("Total", style="white", justify="right")
    summary_table.add_column("Granted", style="green", justify="right")
    summary_table.add_column("Denied", style="red", justify="right")
    summary_table.add_column("Rate", style="yellow", justify="right")

    for service in sorted(results.keys()):
        svc_data = results[service]
        rate = f"{(svc_data['granted'] / svc_data['total'] * 100):.0f}%" if svc_data['total'] > 0 else "0%"
        summary_table.add_row(
            service,
            str(svc_data["total"]),
            str(svc_data["granted"]),
            str(svc_data["denied"]),
            rate,
        )

    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_tested_all}[/bold]",
        f"[bold green]{len(all_granted)}[/bold green]",
        f"[bold red]{total_tested_all - len(all_granted)}[/bold red]",
        f"[bold]{(len(all_granted) / total_tested_all * 100):.0f}%[/bold]" if total_tested_all > 0 else "0%",
    )

    console.print(summary_table)
    console.print()

    # Dangerous permissions
    if dangerous_found:
        console.print(f"[bold red]⚠️  DANGEROUS PERMISSIONS FOUND ({len(set(dangerous_found))}):[/bold red]")
        for perm in sorted(set(dangerous_found)):
            # Mark if new in this run
            new_marker = " [green](NEW)[/green]" if perm in new_permissions_found else ""
            console.print(f"  [red]🔥[/red] {perm}{new_marker}")
        console.print()

    # Granted permissions by service
    if all_granted:
        console.print("[bold green]✅ Granted Permissions by Service (cumulative):[/bold green]")
        for service in sorted(results.keys()):
            granted_list = results[service]["granted_permissions"]
            if granted_list:
                console.print(f"\n[cyan]{service}[/cyan] ({len(granted_list)}):")
                for perm in sorted(granted_list):
                    # Mark source of permission
                    sources = []
                    if perm in merged_test_iam:
                        sources.append("testIam")
                    if perm in merged_api_verified:
                        sources.append("API")
                    source_str = f"[dim]({', '.join(sources)})[/dim]" if sources else ""

                    # Mark if new in this run
                    new_marker = " [green](NEW)[/green]" if perm in new_permissions_found else ""

                    if is_dangerous_permission(perm):
                        console.print(f"  [red]🔥[/red] {perm} [red](DANGEROUS)[/red]{new_marker} {source_str}")
                    else:
                        console.print(f"  [green]✓[/green] {perm}{new_marker} {source_str}")
    else:
        console.print("[yellow]No permissions granted.[/yellow]")

    console.print()

    # Show merge info
    if existing_granted:
        console.print(f"[dim]Merged with {len(existing_granted)} existing permissions from previous runs.[/dim]")

    console.print("[green]Results saved under key 'iam_bruteforce' in session data.[/green]")
    console.print(f"[dim]Total unique permissions found: {len(all_granted)}[/dim]")

    return enumeration_results


def analyze_privilege_escalation_paths(
    session_mgr: "GCPSessionManager",
) -> None:
    """
    Analyze granted permissions and suggest privilege escalation paths.
    """
    results = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("iam_bruteforce")

    if not results:
        console.print("[yellow]No bruteforce results found. Run 'enumerate_bruteforce_permissions' first.[/yellow]")
        return

    granted = set(results.get("all_granted", []))

    console.print("\n[bold blue]🎯 Privilege Escalation Analysis[/bold blue]\n")

    escalation_paths = []

    # 1. Service Account Key Creation
    if "iam.serviceAccountKeys.create" in granted:
        escalation_paths.append({
            "name": "Service Account Key Creation",
            "severity": "CRITICAL",
            "permissions": ["iam.serviceAccountKeys.create"],
            "description": "Can create keys for service accounts → persistent access",
            "command": "gcloud iam service-accounts keys create key.json --iam-account=SA_EMAIL",
        })

    # 2. Token Generation / Impersonation
    impersonation_perms = [
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
    ]
    found_impersonation = [p for p in impersonation_perms if p in granted]
    if found_impersonation:
        escalation_paths.append({
            "name": "Service Account Impersonation",
            "severity": "CRITICAL",
            "permissions": found_impersonation,
            "description": "Can impersonate service accounts → access their permissions",
            "command": "gcloud auth print-access-token --impersonate-service-account=SA_EMAIL",
        })

    # 3. setIamPolicy on project
    if "resourcemanager.projects.setIamPolicy" in granted:
        escalation_paths.append({
            "name": "Project IAM Policy Manipulation",
            "severity": "CRITICAL",
            "permissions": ["resourcemanager.projects.setIamPolicy"],
            "description": "Can modify project IAM policy → grant yourself any role",
            "command": "gcloud projects add-iam-policy-binding PROJECT --member=user:EMAIL --role=roles/owner",
        })

    # 4. Compute metadata manipulation
    metadata_perms = ["compute.instances.setMetadata", "compute.projects.setCommonInstanceMetadata"]
    found_metadata = [p for p in metadata_perms if p in granted]
    if found_metadata:
        escalation_paths.append({
            "name": "Compute Metadata SSH Key Injection",
            "severity": "HIGH",
            "permissions": found_metadata,
            "description": "Can inject SSH keys via metadata → access to instances",
            "command": "gcloud compute instances add-metadata INSTANCE --metadata=ssh-keys='user:ssh-rsa KEY'",
        })

    # 5. Secret access
    if "secretmanager.versions.access" in granted:
        escalation_paths.append({
            "name": "Secret Manager Access",
            "severity": "HIGH",
            "permissions": ["secretmanager.versions.access"],
            "description": "Can read secrets → potential credentials exposure",
            "command": "gcloud secrets versions access latest --secret=SECRET_NAME",
        })

    # 6. Cloud Functions
    if "cloudfunctions.functions.update" in granted or "cloudfunctions.functions.create" in granted:
        escalation_paths.append({
            "name": "Cloud Functions Code Execution",
            "severity": "HIGH",
            "permissions": ["cloudfunctions.functions.update", "cloudfunctions.functions.create"],
            "description": "Can modify/create functions → execute code as function's SA",
            "command": "gcloud functions deploy FUNC --runtime=python39 --trigger-http",
        })

    # 7. GKE pod exec
    if "container.pods.exec" in granted:
        escalation_paths.append({
            "name": "GKE Pod Exec",
            "severity": "HIGH",
            "permissions": ["container.pods.exec"],
            "description": "Can exec into pods → access to pod's SA token",
            "command": "kubectl exec -it POD -- /bin/sh",
        })

    # 8. Role creation
    if "iam.roles.create" in granted or "iam.roles.update" in granted:
        escalation_paths.append({
            "name": "Custom Role Creation",
            "severity": "MEDIUM",
            "permissions": ["iam.roles.create", "iam.roles.update"],
            "description": "Can create/modify custom roles → add dangerous permissions",
            "command": "gcloud iam roles create ROLE --project=PROJECT --permissions=...",
        })

    # 9. Service account list + impersonate (common path)
    if "iam.serviceAccounts.list" in granted:
        escalation_paths.append({
            "name": "Service Account Enumeration",
            "severity": "INFO",
            "permissions": ["iam.serviceAccounts.list"],
            "description": "Can list service accounts → identify targets for impersonation",
            "command": "gcloud iam service-accounts list",
        })

    # Display results
    if escalation_paths:
        for path in escalation_paths:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "INFO": "cyan",
            }.get(path["severity"], "white")

            console.print(f"[bold {severity_color}]■ {path['name']} [{path['severity']}][/bold {severity_color}]")
            console.print(f"  [dim]Permissions:[/dim] {', '.join(path['permissions'])}")
            console.print(f"  [dim]Description:[/dim] {path['description']}")
            console.print(f"  [dim]Example:[/dim] {path['command']}")
            console.print()
    else:
        console.print("[green]No obvious privilege escalation paths found.[/green]")
        console.print("[dim]This doesn't mean escalation is impossible - manual analysis recommended.[/dim]")
