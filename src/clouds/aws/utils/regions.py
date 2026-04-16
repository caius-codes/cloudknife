"""
Shared region resolution and multi-region client utilities for AWS enumeration modules.

This module consolidates the duplicated _resolve_regions_for_* functions
and provides optimized boto3 session/client creation for multi-region operations.
"""

from typing import List, Optional

import boto3
from boto3 import Session as Boto3Session
from rich.console import Console
from rich.prompt import Confirm

from ..aws_session import AWSSessionManager


console = Console()


def resolve_regions(
    session_mgr: AWSSessionManager,
    service_name: str = "service",
    prompt_for_all: bool = True,
) -> List[str]:
    """
    Resolve which AWS regions to use for enumeration based on session configuration.

    Logic:
    - If configured_regions is empty -> [default_region]
    - If configured_regions is an explicit list -> that list
    - If configured_regions == ["all"] -> optionally prompt user, then discover all regions

    Args:
        session_mgr: The SessionManager instance with current session data
        service_name: Name of the service (used in user prompts, e.g., "EC2", "Lambda")
        prompt_for_all: If True, ask user confirmation before scanning all regions

    Returns:
        List of region names to enumerate
    """
    conf = session_mgr.configured_regions

    if not conf:
        return [session_mgr.default_region]

    if conf == ["all"]:
        if prompt_for_all:
            if not Confirm.ask(
                f"[bold yellow]Scan ALL available {service_name} regions?[/bold yellow] "
                "This may be slow and noisy."
            ):
                console.print(
                    "[yellow]Aborting multi-region scan; using default region only.[/yellow]"
                )
                return [session_mgr.default_region]

        return _discover_all_regions(session_mgr)

    # Explicit list of regions
    return conf


def _discover_all_regions(session_mgr: AWSSessionManager) -> List[str]:
    """
    Discover all available AWS regions using EC2 describe_regions API.

    Args:
        session_mgr: The SessionManager instance

    Returns:
        List of all available region names, or [default_region] on failure
    """
    try:
        ec2 = boto3.client("ec2", region_name=session_mgr.default_region)
        resp = ec2.describe_regions(AllRegions=False)
        regions = [r["RegionName"] for r in resp.get("Regions", [])]
        console.print(f"[green]Discovered regions:[/green] {', '.join(regions)}")
        return regions
    except Exception as e:
        console.print(f"[red]Failed to list regions: {str(e)}[/red]")
        return [session_mgr.default_region]


def get_regional_client(
    session_mgr: AWSSessionManager,
    service_name: str,
    region: str,
    _credentials_cache: Optional[dict] = None,
) -> boto3.client:
    """
    Create a boto3 client for a specific service and region.

    This is more efficient than creating a new Boto3Session for each region,
    as it reuses the base session and only changes the region.

    Args:
        session_mgr: The SessionManager instance
        service_name: AWS service name (e.g., "ec2", "lambda", "secretsmanager")
        region: AWS region name
        _credentials_cache: Optional dict to cache extracted credentials (internal use)

    Returns:
        boto3 client for the specified service and region
    """
    base_session = session_mgr.get_boto3_session()

    # For simple cases, just create a client with a different region
    # boto3 handles credential reuse internally
    return base_session.client(service_name, region_name=region)


class RegionalClientFactory:
    """
    Factory for creating boto3 clients across multiple regions efficiently.

    This class caches credentials extracted from the base session to avoid
    repeated credential lookups when creating clients for multiple regions.

    Usage:
        factory = RegionalClientFactory(session_mgr)
        for region in regions:
            ec2 = factory.get_client("ec2", region)
            # ... use client
    """

    def __init__(self, session_mgr: AWSSessionManager):
        """
        Initialize the factory with a SessionManager.

        Args:
            session_mgr: The SessionManager instance with current credentials
        """
        self.session_mgr = session_mgr
        self._base_session = session_mgr.get_boto3_session()
        self._credentials = self._extract_credentials()

    def _extract_credentials(self) -> dict:
        """Extract and cache credentials from the base session."""
        creds = self._base_session.get_credentials()
        return {
            "aws_access_key_id": creds.access_key,
            "aws_secret_access_key": creds.secret_key,
            "aws_session_token": creds.token,
        }

    def get_client(self, service_name: str, region: str) -> boto3.client:
        """
        Get a boto3 client for the specified service and region.

        Args:
            service_name: AWS service name (e.g., "ec2", "lambda")
            region: AWS region name

        Returns:
            boto3 client configured for the specified service and region
        """
        # Create a new session with cached credentials and the target region
        regional_session = Boto3Session(
            aws_access_key_id=self._credentials["aws_access_key_id"],
            aws_secret_access_key=self._credentials["aws_secret_access_key"],
            aws_session_token=self._credentials["aws_session_token"],
            region_name=region,
        )
        return regional_session.client(service_name)

    def get_session(self, region: str) -> Boto3Session:
        """
        Get a boto3 Session for the specified region.

        Args:
            region: AWS region name

        Returns:
            boto3 Session configured for the specified region
        """
        return Boto3Session(
            aws_access_key_id=self._credentials["aws_access_key_id"],
            aws_secret_access_key=self._credentials["aws_secret_access_key"],
            aws_session_token=self._credentials["aws_session_token"],
            region_name=region,
        )
