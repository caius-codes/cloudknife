"""
GCP Enumeration modules - alphabetically sorted.
"""

from .cloud_build import (
    describe_cloud_build,
    enumerate_cloud_build_history,
    enumerate_cloud_build_triggers,
)
from .cloud_functions import enumerate_cloud_functions
from .cloud_run_services import (
    describe_cloud_run_service,
    enumerate_cloud_run_services,
)
from .cloud_sql import enumerate_cloud_sql
from .compute_instances import describe_instance, enumerate_compute_instances
from .compute_metadata import enumerate_compute_metadata, describe_metadata_detail
from .enumerate_artifact_packages import enumerate_artifact_packages
from .enumerate_artifact_repositories import enumerate_artifact_repositories
from .enumerate_artifact_versions import enumerate_artifact_versions
from .google_drive import (
    describe_file_permissions,
    enumerate_drive_files,
    search_drive_files,
)
from .iam_bruteforce import enumerate_bruteforce_permissions, analyze_privilege_escalation_paths
from .iam_policies import enumerate_iam_policies
from .parameter_manager import enumerate_parameters
from .quick_enum import quick_enum
from .resource_permissions import enumerate_resource_permissions
from .role_describe import describe_role, enumerate_predefined_roles
from .sa_exploitation_targets import (
    enumerate_delegation_chains,
    enumerate_exploitable_sas,
    test_sa_permission,
)
from .secret_manager import enumerate_secrets
from .service_account_iam import describe_service_account_iam_policy
from .source_repositories import enumerate_source_repositories
from .storage_buckets import enumerate_storage_buckets
from .storage_objects import enumerate_bucket_objects

__all__ = [
    "analyze_privilege_escalation_paths",
    "describe_cloud_build",
    "describe_cloud_run_service",
    "describe_file_permissions",
    "describe_instance",
    "describe_metadata_detail",
    "describe_role",
    "describe_service_account_iam_policy",
    "enumerate_artifact_packages",
    "enumerate_artifact_repositories",
    "enumerate_artifact_versions",
    "enumerate_bruteforce_permissions",
    "enumerate_bucket_objects",
    "enumerate_cloud_build_history",
    "enumerate_cloud_build_triggers",
    "enumerate_cloud_functions",
    "enumerate_cloud_run_services",
    "enumerate_cloud_sql",
    "enumerate_compute_instances",
    "enumerate_compute_metadata",
    "enumerate_delegation_chains",
    "enumerate_drive_files",
    "enumerate_exploitable_sas",
    "enumerate_iam_policies",
    "enumerate_parameters",
    "enumerate_predefined_roles",
    "enumerate_resource_permissions",
    "enumerate_secrets",
    "enumerate_source_repositories",
    "enumerate_storage_buckets",
    "quick_enum",
    "search_drive_files",
    "test_sa_permission",
]
