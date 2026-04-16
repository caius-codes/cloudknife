"""
GCP project and zone utilities for Cloud Knife.

Provides shared functions for:
- Resolving which projects to enumerate
- Getting all available zones
- Iterating across projects/zones efficiently
"""

from typing import List, TYPE_CHECKING

from google.cloud import compute_v1

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager


def resolve_projects(session_mgr: "GCPSessionManager") -> List[str]:
    """
    Resolve which GCP projects to enumerate.

    Order of precedence:
    1. Explicitly configured projects (session_mgr.configured_projects)
    2. Auto-discovered accessible projects
    3. Default project only

    Returns:
        List of project IDs to enumerate
    """
    # Check for explicitly configured projects
    configured = session_mgr.configured_projects
    if configured:
        return configured

    # Try to auto-discover accessible projects
    discovered = session_mgr.discover_accessible_projects()
    if discovered:
        return discovered

    # Fall back to default project
    default = session_mgr.default_project
    return [default] if default else []


def get_all_zones(session_mgr: "GCPSessionManager", project_id: str = None) -> List[str]:
    """
    Get all available GCP zones with automatic caching.

    If configured_zones is set, returns those.
    Otherwise fetches all zones from the Compute API and caches the result.

    Args:
        session_mgr: GCP session manager
        project_id: Optional project ID (uses default if not specified)

    Returns:
        List of zone names (e.g., ["us-central1-a", "us-east1-b", ...])
    """
    # Check for explicitly configured zones
    configured = session_mgr.configured_zones
    if configured:
        return configured

    # Check session cache (avoids redundant API calls)
    cached_zones = getattr(session_mgr, '_cached_zones', None)
    if cached_zones:
        return cached_zones

    # Fetch all zones from the API (only on first call)
    credentials = session_mgr.get_credentials()
    if not credentials:
        return [session_mgr.default_zone]

    project = project_id or session_mgr.default_project
    if not project:
        return [session_mgr.default_zone]

    try:
        zones_client = compute_v1.ZonesClient(credentials=credentials)
        zones = []

        for zone in zones_client.list(project=project):
            if zone.status == "UP":
                zones.append(zone.name)

        zones = sorted(zones) if zones else [session_mgr.default_zone]

        # Cache in session for subsequent calls
        session_mgr._cached_zones = zones

        return zones

    except Exception:
        return [session_mgr.default_zone]


def get_all_regions(session_mgr: "GCPSessionManager", project_id: str = None) -> List[str]:
    """
    Get all available GCP regions.

    Args:
        session_mgr: GCP session manager
        project_id: Optional project ID (uses default if not specified)

    Returns:
        List of region names (e.g., ["us-central1", "us-east1", ...])
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        return ["us-central1"]

    project = project_id or session_mgr.default_project
    if not project:
        return ["us-central1"]

    try:
        regions_client = compute_v1.RegionsClient(credentials=credentials)
        regions = []

        for region in regions_client.list(project=project):
            if region.status == "UP":
                regions.append(region.name)

        return sorted(regions) if regions else ["us-central1"]

    except Exception:
        return ["us-central1"]
