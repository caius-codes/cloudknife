"""
GCP Resource Permission Enumeration Module.

Uses two GCP APIs in combination:
1. queryTestablePermissions - discovers all permissions applicable to a resource
2. testIamPermissions - checks which of those permissions the current identity has

This catches permissions that project-level bruteforce misses:
- Permissions granted at resource level (bucket-level ACLs, function invoker, etc.)
- Fine-grained permissions on specific resources

Supported resource types:
- storage   (Cloud Storage buckets)
- functions (Cloud Functions v1/v2)
- compute   (Compute Engine instances)
- pubsub    (Pub/Sub topics)
- bigquery  (BigQuery datasets)
- run       (Cloud Run services)
- sa        (Service Accounts)

Usage:
    enumerate_resource_permissions <type> <name>
    enumerate_resource_permissions storage my-bucket
    enumerate_resource_permissions functions my-function --project proj --location us-central1
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()

# queryTestablePermissions API
QUERY_TESTABLE_PERMISSIONS_URL = "https://iam.googleapis.com/v1/permissions:queryTestablePermissions"

# Maximum permissions per testIamPermissions call
MAX_PERMISSIONS_PER_CALL = 100

# ──────────────────────────────────────────────────────────
# Full Resource Name builders
# ──────────────────────────────────────────────────────────

RESOURCE_TYPE_MAP = {
    "storage": {
        "label": "Cloud Storage Bucket",
        "full_resource_name": "//storage.googleapis.com/projects/_/buckets/{name}",
        "test_endpoint": "https://storage.googleapis.com/storage/v1/b/{name}/iam/testPermissions",
        "test_method": "GET",  # Storage uses GET with query params
        "requires_project": False,
        "requires_location": False,
        # Storage testPermissions only accepts storage.* permissions
        "permission_prefixes": ["storage."],
        # These cause 400 on the storage testPermissions endpoint
        "excluded_permissions": [
            "storage.objects.getIamPolicy",
            "storage.objects.setIamPolicy",
        ],
    },
    "functions": {
        "label": "Cloud Function",
        "full_resource_name": "//cloudfunctions.googleapis.com/projects/{project}/locations/{location}/functions/{name}",
        "test_endpoint": "https://cloudfunctions.googleapis.com/v1/projects/{project}/locations/{location}/functions/{name}:testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_location": True,
        "default_location": "us-central1",
        "permission_prefixes": ["cloudfunctions."],
    },
    "compute": {
        "label": "Compute Engine Instance",
        "full_resource_name": "//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}",
        "test_endpoint": "https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{name}/testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_zone": True,
        "default_zone": "us-central1-a",
        "permission_prefixes": ["compute."],
    },
    "pubsub": {
        "label": "Pub/Sub Topic",
        "full_resource_name": "//pubsub.googleapis.com/projects/{project}/topics/{name}",
        "test_endpoint": "https://pubsub.googleapis.com/v1/projects/{project}/topics/{name}:testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_location": False,
        "permission_prefixes": ["pubsub."],
    },
    "bigquery": {
        "label": "BigQuery Dataset",
        "full_resource_name": "//bigquery.googleapis.com/projects/{project}/datasets/{name}",
        "test_endpoint": "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{name}:testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_location": False,
        "permission_prefixes": ["bigquery."],
    },
    "run": {
        "label": "Cloud Run Service",
        "full_resource_name": "//run.googleapis.com/projects/{project}/locations/{location}/services/{name}",
        "test_endpoint": "https://run.googleapis.com/v1/projects/{project}/locations/{location}/services/{name}:testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_location": True,
        "default_location": "us-central1",
        "permission_prefixes": ["run."],
    },
    "sa": {
        "label": "Service Account",
        "full_resource_name": "//iam.googleapis.com/projects/{project}/serviceAccounts/{name}",
        "test_endpoint": "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{name}:testIamPermissions",
        "test_method": "POST",
        "requires_project": True,
        "requires_location": False,
        "permission_prefixes": ["iam."],
    },
}

# Permissions considered dangerous / interesting for pentest
DANGEROUS_PERMISSION_KEYWORDS = [
    "delete", "create", "update", "setIamPolicy", "getIamPolicy",
    "write", "admin", "invoke", "signBlob", "signJwt",
    "getAccessToken", "actAs", "implicitDelegation",
    "setMetadata", "osLogin", "osAdminLogin",
    "getData", "get_iam_policy", "set_iam_policy",
]


def _get_access_token(session_mgr: "GCPSessionManager") -> Optional[str]:
    """Get access token from session credentials."""
    auth_method = session_mgr.current_session_data.get("auth_method")

    if auth_method == "access_token":
        return session_mgr.current_session_data.get("access_token")
    else:
        credentials = session_mgr.get_credentials()
        if credentials:
            try:
                from google.auth.transport.requests import Request
                credentials.refresh(Request())
                return credentials.token
            except Exception:
                pass
    return None


def _is_dangerous_permission(permission: str) -> bool:
    """Check if a permission is considered dangerous/interesting."""
    perm_lower = permission.lower()
    return any(keyword.lower() in perm_lower for keyword in DANGEROUS_PERMISSION_KEYWORDS)


# ──────────────────────────────────────────────────────────
# Step 1: queryTestablePermissions
# ──────────────────────────────────────────────────────────

def query_testable_permissions(
    token: str,
    full_resource_name: str,
) -> List[str]:
    """
    Call queryTestablePermissions to discover all testable permissions for a resource.

    Args:
        token: Access token
        full_resource_name: Full GCP resource name (e.g. //storage.googleapis.com/...)

    Returns:
        List of permission strings
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    all_permissions: List[str] = []
    page_token: Optional[str] = None

    while True:
        body: Dict[str, Any] = {
            "fullResourceName": full_resource_name,
            "pageSize": 1000,
        }
        if page_token:
            body["pageToken"] = page_token

        response = requests.post(
            QUERY_TESTABLE_PERMISSIONS_URL,
            headers=headers,
            json=body,
            timeout=30,
        )

        if response.status_code != 200:
            console.print(f"[red]queryTestablePermissions failed: {response.status_code}[/red]")
            try:
                error_detail = response.json().get("error", {}).get("message", response.text[:200])
                console.print(f"[red]Error: {error_detail}[/red]")
            except Exception:
                console.print(f"[red]{response.text[:200]}[/red]")
            return []

        data = response.json()
        permissions = data.get("permissions", [])
        for perm in permissions:
            perm_name = perm.get("name", "")
            if perm_name:
                all_permissions.append(perm_name)

        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return all_permissions


# ──────────────────────────────────────────────────────────
# Step 2: testIamPermissions on the resource
# ──────────────────────────────────────────────────────────

def test_resource_permissions(
    token: str,
    resource_config: Dict[str, Any],
    format_params: Dict[str, str],
    permissions: List[str],
) -> List[str]:
    """
    Test which permissions the current identity actually has on the resource.

    Args:
        token: Access token
        resource_config: Resource type configuration from RESOURCE_TYPE_MAP
        format_params: Parameters to format the endpoint URL (name, project, etc.)
        permissions: List of permissions to test

    Returns:
        List of granted permission strings
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    test_endpoint = resource_config["test_endpoint"].format(**format_params)
    test_method = resource_config.get("test_method", "POST")
    granted: List[str] = []

    # Test in batches of MAX_PERMISSIONS_PER_CALL
    for i in range(0, len(permissions), MAX_PERMISSIONS_PER_CALL):
        batch = permissions[i:i + MAX_PERMISSIONS_PER_CALL]

        try:
            if test_method == "GET":
                # Storage-style: GET with ?permissions= query params
                params = [("permissions", p) for p in batch]
                response = requests.get(
                    test_endpoint,
                    headers=headers,
                    params=params,
                    timeout=30,
                )
            else:
                # Standard POST with body
                response = requests.post(
                    test_endpoint,
                    headers=headers,
                    json={"permissions": batch},
                    timeout=30,
                )

            if response.status_code == 200:
                data = response.json()
                # Storage returns "permissions", others return "permissions"
                batch_granted = data.get("permissions", [])
                granted.extend(batch_granted)
            elif response.status_code == 403:
                # No permission to test - skip silently
                pass
            elif response.status_code == 404:
                console.print(f"[red]Resource not found. Check name and parameters.[/red]")
                return granted
            else:
                console.print(
                    f"[yellow]testIamPermissions batch {i // MAX_PERMISSIONS_PER_CALL + 1}: "
                    f"HTTP {response.status_code}[/yellow]"
                )

        except requests.exceptions.Timeout:
            console.print(f"[yellow]Timeout on batch {i // MAX_PERMISSIONS_PER_CALL + 1}, skipping[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Error testing batch: {e}[/yellow]")

    return granted


# ──────────────────────────────────────────────────────────
# Main enumeration function
# ──────────────────────────────────────────────────────────

def enumerate_resource_permissions(
    session_mgr: "GCPSessionManager",
    resource_type: Optional[str] = None,
    resource_name: Optional[str] = None,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    zone: Optional[str] = None,
) -> List[str]:
    """
    Enumerate permissions on a specific GCP resource.

    Combines queryTestablePermissions + testIamPermissions to discover
    what the current identity can do on a specific resource.

    Args:
        session_mgr: GCP session manager with valid credentials
        resource_type: Resource type (storage, functions, compute, pubsub, bigquery, run, sa)
        resource_name: Resource name (bucket name, function name, etc.)
        project_id: Project ID (required for most resources)
        location: Location/region (for functions, run)
        zone: Zone (for compute instances)

    Returns:
        List of granted permissions
    """
    console.print("\n[bold blue]🔍 Resource Permission Enumeration[/bold blue]")
    console.print("[dim]Discover permissions on a specific resource via queryTestablePermissions[/dim]\n")

    # Interactive prompts if not provided
    if not resource_type:
        console.print("[bold]Supported resource types:[/bold]")
        for key, config in RESOURCE_TYPE_MAP.items():
            console.print(f"  [cyan]{key:12s}[/cyan] {config['label']}")
        console.print()
        resource_type = Prompt.ask(
            "[cyan]Resource type[/cyan]",
            choices=list(RESOURCE_TYPE_MAP.keys()),
        )

    if resource_type not in RESOURCE_TYPE_MAP:
        console.print(f"[red]Unknown resource type: {resource_type}[/red]")
        console.print(f"[dim]Supported: {', '.join(RESOURCE_TYPE_MAP.keys())}[/dim]")
        return []

    config = RESOURCE_TYPE_MAP[resource_type]

    if not resource_name:
        resource_name = Prompt.ask(f"[cyan]{config['label']} name[/cyan]")

    if not resource_name:
        console.print("[red]Resource name is required.[/red]")
        return []

    # Collect required parameters
    format_params: Dict[str, str] = {"name": resource_name}

    if config.get("requires_project", False):
        if not project_id:
            default_project = session_mgr.current_session_data.get("project_id", "")
            project_id = Prompt.ask(
                "[cyan]Project ID[/cyan]",
                default=default_project if default_project else "",
            )
        if not project_id:
            console.print("[red]Project ID is required for this resource type.[/red]")
            return []
        format_params["project"] = project_id

    if config.get("requires_location", False):
        if not location:
            default_loc = config.get("default_location", "us-central1")
            location = Prompt.ask("[cyan]Location[/cyan]", default=default_loc)
        format_params["location"] = location

    if config.get("requires_zone", False):
        if not zone:
            default_zone = config.get("default_zone", "us-central1-a")
            zone = Prompt.ask("[cyan]Zone[/cyan]", default=default_zone)
        format_params["zone"] = zone

    # Get access token
    token = _get_access_token(session_mgr)
    if not token:
        console.print("[red]No valid credentials. Use set_credentials, set_adc, or set_token first.[/red]")
        return []

    # Build full resource name
    full_resource_name = config["full_resource_name"].format(**format_params)
    console.print(f"[dim]Full resource name: {full_resource_name}[/dim]")

    # Step 1: Query testable permissions
    console.print("[dim]Querying testable permissions...[/dim]")
    testable_permissions = query_testable_permissions(token, full_resource_name)

    if not testable_permissions:
        console.print("[yellow]No testable permissions found for this resource.[/yellow]")
        return []

    console.print(f"[green]Found {len(testable_permissions)} testable permissions[/green]")

    # Filter permissions to only those accepted by the service's testIamPermissions endpoint
    # Each service API only accepts its own permissions (e.g., Storage only accepts storage.*)
    permission_prefixes = config.get("permission_prefixes")
    excluded_permissions = set(config.get("excluded_permissions", []))
    filtered_permissions = testable_permissions

    if permission_prefixes:
        filtered_permissions = [
            p for p in filtered_permissions
            if any(p.startswith(prefix) for prefix in permission_prefixes)
        ]

    if excluded_permissions:
        filtered_permissions = [
            p for p in filtered_permissions
            if p not in excluded_permissions
        ]

    if len(filtered_permissions) < len(testable_permissions):
        console.print(
            f"[dim]Filtered to {len(filtered_permissions)} service-specific permissions "
            f"(removed {len(testable_permissions) - len(filtered_permissions)} unsupported by testIamPermissions endpoint)[/dim]"
        )

    if not filtered_permissions:
        console.print("[yellow]No permissions left after filtering for this service.[/yellow]")
        return []

    # Step 2: Test which permissions we actually have
    console.print(f"[dim]Testing permissions ({len(filtered_permissions)} in batches of {MAX_PERMISSIONS_PER_CALL})...[/dim]")
    granted_permissions = test_resource_permissions(
        token, config, format_params, filtered_permissions
    )

    # Display results
    _display_results(
        resource_type=resource_type,
        resource_name=resource_name,
        config=config,
        format_params=format_params,
        testable_permissions=filtered_permissions,
        granted_permissions=granted_permissions,
    )

    # Save to enumerated data
    if session_mgr.current_session:
        save_key = f"resource_permissions_{resource_type}_{resource_name}"
        session_mgr.save_enumeration_data(save_key, {
            "resource_type": resource_type,
            "resource_name": resource_name,
            "full_resource_name": full_resource_name,
            "testable_count": len(testable_permissions),
            "tested_count": len(filtered_permissions),
            "granted_permissions": granted_permissions,
            "granted_count": len(granted_permissions),
        })

    return granted_permissions


def _display_results(
    resource_type: str,
    resource_name: str,
    config: Dict[str, Any],
    format_params: Dict[str, str],
    testable_permissions: List[str],
    granted_permissions: List[str],
) -> None:
    """Display enumeration results in a formatted table."""

    if not granted_permissions:
        console.print(
            f"\n[yellow]No permissions granted on {config['label']}: {resource_name}[/yellow]"
        )
        console.print(f"[dim]Tested {len(testable_permissions)} permissions, 0 granted.[/dim]")
        return

    # Separate dangerous from normal
    dangerous = [p for p in granted_permissions if _is_dangerous_permission(p)]
    normal = [p for p in granted_permissions if not _is_dangerous_permission(p)]

    # Summary
    console.print(
        f"\n[bold green]Granted {len(granted_permissions)}/{len(testable_permissions)} permissions "
        f"on {config['label']}: {resource_name}[/bold green]"
    )

    if dangerous:
        console.print(f"[bold red]⚠  {len(dangerous)} dangerous permission(s) found![/bold red]")

    # Build table
    table = Table(
        title=f"Permissions on {resource_type}://{resource_name}",
        show_lines=False,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Permission", style="white", overflow="fold", no_wrap=False)
    table.add_column("Risk", justify="center")

    idx = 1

    # Dangerous first
    for perm in sorted(dangerous):
        table.add_row(str(idx), f"[bold red]{perm}[/bold red]", "[red]DANGEROUS[/red]")
        idx += 1

    # Then normal
    for perm in sorted(normal):
        table.add_row(str(idx), perm, "[dim]normal[/dim]")
        idx += 1

    console.print(table)

    # Group by service prefix
    services: Dict[str, int] = {}
    for perm in granted_permissions:
        svc = perm.split(".")[0] if "." in perm else "other"
        services[svc] = services.get(svc, 0) + 1

    console.print("\n[bold]Permissions by service:[/bold]")
    for svc in sorted(services, key=services.get, reverse=True):
        console.print(f"  [cyan]{svc}[/cyan]: {services[svc]}")

    console.print()
