"""
GCP Cloud Storage Bucket Enumeration for Cloud Knife.

Enumerates all Cloud Storage buckets, including:
- Bucket metadata (name, location, storage class)
- Access control (IAM policies, ACLs)
- Public access settings
- Versioning and lifecycle rules
- Encryption configuration

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

from typing import List, Dict, Any, TYPE_CHECKING, Optional

import requests
from rich.console import Console
from rich.table import Table
from google.cloud import storage

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# GCS JSON API base URL
GCS_API_BASE = "https://storage.googleapis.com/storage/v1"


def enumerate_storage_buckets(session_mgr: "GCPSessionManager", bucket_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Enumerate Cloud Storage buckets.

    Uses REST API for access_token auth, client library for service_account/ADC.

    Args:
        session_mgr: GCP session manager with valid credentials
        bucket_name: Optional specific bucket name to analyze. If None, lists all buckets across all projects.

    Returns:
        List of bucket dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    auth_method = session_mgr.current_session_data.get("auth_method")
    all_buckets: List[Dict[str, Any]] = []

    # If specific bucket name provided, analyze only that bucket
    if bucket_name:
        console.print(f"[bold]Analyzing specific Cloud Storage bucket: {bucket_name}[/bold]")
        try:
            if auth_method == "access_token":
                bucket_info = _get_bucket_rest_api(session_mgr, bucket_name)
            else:
                bucket_info = _get_bucket_client_lib(session_mgr, bucket_name, credentials)

            if bucket_info:
                all_buckets.append(bucket_info)
        except Exception as e:
            console.print(f"[red]Error analyzing bucket {bucket_name}: {str(e)}[/red]")
            return []
    else:
        # No specific bucket - enumerate all buckets across projects
        console.print("[bold]Enumerating all Cloud Storage buckets...[/bold]")

        projects = resolve_projects(session_mgr)
        if not projects:
            console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
            return []

        for project in projects:
            console.print(f"[dim]Scanning project: {project}[/dim]")

            try:
                if auth_method == "access_token":
                    # Use REST API for access_token auth
                    buckets = _enumerate_buckets_rest_api(session_mgr, project)
                else:
                    # Use client library for service_account/ADC
                    buckets = _enumerate_buckets_client_lib(session_mgr, project, credentials)

                all_buckets.extend(buckets)

            except Exception as e:
                console.print(f"[dim red]Error scanning project {project}: {str(e)}[/dim red]")
                continue

    # Save enumeration results
    session_mgr.save_enumeration_data("storage_buckets", all_buckets)

    # Display results table
    _display_buckets_table(all_buckets)

    return all_buckets


def _get_bucket_rest_api(
    session_mgr: "GCPSessionManager", bucket_name: str
) -> Optional[Dict[str, Any]]:
    """Get single bucket metadata using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return None

    headers = {"Authorization": f"Bearer {token}"}

    # Get bucket metadata
    url = f"{GCS_API_BASE}/b/{bucket_name}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            console.print(f"[red]Failed to get bucket {bucket_name}: HTTP {response.status_code}[/red]")
            return None

        item = response.json()

        # Get IAM policy for the bucket
        is_public = False
        iam_bindings = []
        try:
            iam_url = f"{GCS_API_BASE}/b/{bucket_name}/iam"
            iam_response = requests.get(iam_url, headers=headers, timeout=30)
            if iam_response.status_code == 200:
                policy = iam_response.json()
                for binding in policy.get("bindings", []):
                    iam_bindings.append({
                        "role": binding.get("role"),
                        "members": binding.get("members", []),
                    })
                    # Check for public access
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        is_public = True
        except Exception:
            pass

        # Extract IAM configuration
        iam_config = item.get("iamConfiguration", {})
        public_access_prevention = iam_config.get("publicAccessPrevention", "inherited")
        uniform_access = iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)

        # Extract lifecycle rules
        lifecycle_rules = []
        lifecycle = item.get("lifecycle", {})
        for rule in lifecycle.get("rule", []):
            lifecycle_rules.append({
                "action": rule.get("action", {}),
                "condition": rule.get("condition", {}),
            })

        # Build bucket record (match format from _enumerate_buckets_rest_api)
        bucket_info = {
            "project": item.get("projectNumber"),  # Note: returns projectNumber not projectId
            "name": item.get("name"),
            "id": item.get("id"),
            "location": item.get("location"),
            "location_type": item.get("locationType"),
            "storage_class": item.get("storageClass"),
            "created": item.get("timeCreated"),
            "versioning_enabled": item.get("versioning", {}).get("enabled", False),
            "is_public": is_public,
            "public_access_prevention": public_access_prevention,
            "uniform_bucket_level_access": uniform_access,
            "iam_bindings": iam_bindings,
            "lifecycle_rules": lifecycle_rules,
            "default_kms_key": item.get("encryption", {}).get("defaultKmsKeyName"),
            "labels": item.get("labels", {}),
            "requester_pays": item.get("billing", {}).get("requesterPays", False),
        }

        return bucket_info

    except Exception as e:
        console.print(f"[red]Error getting bucket {bucket_name}: {str(e)}[/red]")
        return None


def _get_bucket_client_lib(
    session_mgr: "GCPSessionManager", bucket_name: str, credentials: Any
) -> Optional[Dict[str, Any]]:
    """Get single bucket metadata using client library (for service_account/ADC)."""
    try:
        client = storage.Client(credentials=credentials)
        bucket = client.get_bucket(bucket_name)

        # Get IAM policy
        is_public = False
        iam_bindings = []
        public_access_prevention = "inherited"
        uniform_access = False

        try:
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                iam_bindings.append({
                    "role": binding["role"],
                    "members": list(binding["members"]),
                })
                # Check for public access
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    is_public = True
        except Exception:
            pass

        # Get public access prevention setting
        try:
            iam_config = bucket.iam_configuration
            if hasattr(iam_config, "public_access_prevention"):
                public_access_prevention = iam_config.public_access_prevention or "inherited"
            if hasattr(iam_config, "uniform_bucket_level_access_enabled"):
                uniform_access = iam_config.uniform_bucket_level_access_enabled
            else:
                uniform_access = False
        except Exception:
            uniform_access = False

        # Get lifecycle rules
        lifecycle_rules = []
        if bucket.lifecycle_rules:
            for rule in bucket.lifecycle_rules:
                lifecycle_rules.append({
                    "action": rule.get("action", {}),
                    "condition": rule.get("condition", {}),
                })

        # Build bucket record (match format from _enumerate_buckets_client_lib)
        # Note: cannot get project from bucket object, need to extract from session
        project = session_mgr.current_session_data.get('project_id', bucket.project_number)

        bucket_info = {
            "project": project,
            "name": bucket.name,
            "id": bucket.id,
            "location": bucket.location,
            "location_type": bucket.location_type,
            "storage_class": bucket.storage_class,
            "created": bucket.time_created.isoformat() if bucket.time_created else None,
            "versioning_enabled": bucket.versioning_enabled,
            "is_public": is_public,
            "public_access_prevention": public_access_prevention,
            "uniform_bucket_level_access": uniform_access,
            "iam_bindings": iam_bindings,
            "lifecycle_rules": lifecycle_rules,
            "default_kms_key": bucket.default_kms_key_name,
            "labels": bucket.labels or {},
            "requester_pays": bucket.requester_pays,
        }

        return bucket_info

    except Exception as e:
        console.print(f"[red]Error getting bucket {bucket_name}: {str(e)}[/red]")
        return None


def _enumerate_buckets_rest_api(
    session_mgr: "GCPSessionManager", project: str
) -> List[Dict[str, Any]]:
    """Enumerate buckets using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    buckets: List[Dict[str, Any]] = []

    # List buckets for project
    url = f"{GCS_API_BASE}/b"
    params = {"project": project}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code != 200:
            return []

        data = response.json()
        items = data.get("items", [])

        for item in items:
            bucket_name = item.get("name")

            # Get IAM policy for the bucket
            is_public = False
            iam_bindings = []
            try:
                iam_url = f"{GCS_API_BASE}/b/{bucket_name}/iam"
                iam_response = requests.get(iam_url, headers=headers, timeout=30)
                if iam_response.status_code == 200:
                    policy = iam_response.json()
                    for binding in policy.get("bindings", []):
                        iam_bindings.append({
                            "role": binding.get("role"),
                            "members": binding.get("members", []),
                        })
                        # Check for public access
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            is_public = True
            except Exception:
                pass

            # Extract IAM configuration
            iam_config = item.get("iamConfiguration", {})
            public_access_prevention = iam_config.get("publicAccessPrevention", "inherited")
            uniform_access = iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)

            # Extract lifecycle rules
            lifecycle_rules = []
            lifecycle = item.get("lifecycle", {})
            for rule in lifecycle.get("rule", []):
                lifecycle_rules.append({
                    "action": rule.get("action", {}),
                    "condition": rule.get("condition", {}),
                })

            # Build bucket record
            bucket_data = {
                "project": project,
                "name": bucket_name,
                "id": item.get("id"),
                "location": item.get("location"),
                "location_type": item.get("locationType"),
                "storage_class": item.get("storageClass"),
                "created": item.get("timeCreated"),
                "versioning_enabled": item.get("versioning", {}).get("enabled", False),
                "is_public": is_public,
                "public_access_prevention": public_access_prevention,
                "uniform_bucket_level_access": uniform_access,
                "iam_bindings": iam_bindings,
                "lifecycle_rules": lifecycle_rules,
                "default_kms_key": item.get("encryption", {}).get("defaultKmsKeyName"),
                "labels": item.get("labels", {}),
                "requester_pays": item.get("billing", {}).get("requesterPays", False),
            }

            buckets.append(bucket_data)

    except Exception:
        pass

    return buckets


def _enumerate_buckets_client_lib(
    session_mgr: "GCPSessionManager", project: str, credentials
) -> List[Dict[str, Any]]:
    """Enumerate buckets using client library (for service_account/ADC)."""
    buckets: List[Dict[str, Any]] = []

    # Create storage client for this project
    storage_client = storage.Client(
        credentials=credentials,
        project=project,
    )

    for bucket in storage_client.list_buckets():
        # Check for public access
        is_public = False
        public_access_prevention = "unknown"
        iam_bindings = []

        try:
            # Get IAM policy
            policy = bucket.get_iam_policy(requested_policy_version=3)

            for binding in policy.bindings:
                iam_bindings.append({
                    "role": binding["role"],
                    "members": list(binding["members"]),
                })

                # Check for public access
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    is_public = True

        except Exception:
            pass

        # Get public access prevention setting
        try:
            iam_config = bucket.iam_configuration
            if hasattr(iam_config, "public_access_prevention"):
                public_access_prevention = iam_config.public_access_prevention or "inherited"
            if hasattr(iam_config, "uniform_bucket_level_access_enabled"):
                uniform_access = iam_config.uniform_bucket_level_access_enabled
            else:
                uniform_access = False
        except Exception:
            uniform_access = False

        # Get lifecycle rules
        lifecycle_rules = []
        if bucket.lifecycle_rules:
            for rule in bucket.lifecycle_rules:
                lifecycle_rules.append({
                    "action": rule.get("action", {}),
                    "condition": rule.get("condition", {}),
                })

        # Build bucket record
        bucket_data = {
            "project": project,
            "name": bucket.name,
            "id": bucket.id,
            "location": bucket.location,
            "location_type": bucket.location_type,
            "storage_class": bucket.storage_class,
            "created": bucket.time_created.isoformat() if bucket.time_created else None,
            "versioning_enabled": bucket.versioning_enabled,
            "is_public": is_public,
            "public_access_prevention": public_access_prevention,
            "uniform_bucket_level_access": uniform_access,
            "iam_bindings": iam_bindings,
            "lifecycle_rules": lifecycle_rules,
            "default_kms_key": bucket.default_kms_key_name,
            "labels": dict(bucket.labels) if bucket.labels else {},
            "requester_pays": bucket.requester_pays,
        }

        buckets.append(bucket_data)

    return buckets


def _display_buckets_table(buckets: List[Dict[str, Any]]) -> None:
    """Display buckets in a Rich table."""
    if not buckets:
        console.print("[yellow]No Cloud Storage buckets found.[/yellow]")
        return

    table = Table(title=f"Cloud Storage Buckets ({len(buckets)} found)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Bucket Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Location")
    table.add_column("Storage Class")
    table.add_column("Public", style="bold")
    table.add_column("Versioning")
    table.add_column("Encryption")

    for bucket in buckets:
        # Format public status
        if bucket["is_public"]:
            public_styled = "[bold red]PUBLIC[/bold red]"
        else:
            public_styled = "[green]Private[/green]"

        # Format versioning
        versioning = "[green]ON[/green]" if bucket["versioning_enabled"] else "[dim]OFF[/dim]"

        # Format encryption
        if bucket["default_kms_key"]:
            encryption = "[cyan]CMEK[/cyan]"
        else:
            encryption = "[dim]Google-managed[/dim]"

        table.add_row(
            bucket["project"],
            bucket["name"],
            f"{bucket['location']} ({bucket['location_type']})",
            bucket["storage_class"],
            public_styled,
            versioning,
            encryption,
        )

    console.print(table)

    # Show warning for public buckets
    public_buckets = [b for b in buckets if b["is_public"]]
    if public_buckets:
        console.print(f"\n[bold red]Warning: {len(public_buckets)} bucket(s) are publicly accessible![/bold red]")
        for bucket in public_buckets:
            console.print(f"  [red]- gs://{bucket['name']}[/red]")
