# src/data/gcp_iam_permissions.py
"""
GCP IAM Permissions for bruteforce enumeration.

Organized by exploitation priority:
- FAST_PERMISSIONS: High-value permissions for privilege escalation, impersonation, secrets
- FULL_PERMISSIONS: Common services with deeper coverage
- LOW_PERMISSIONS: Less exploitable but comprehensive enumeration
"""

from typing import Dict, List


# =============================================================================
# FAST_PERMISSIONS (default) - Most exploitable permissions for pentest
# Focus: privilege escalation, impersonation, secrets access, persistence
# =============================================================================
FAST_PERMISSIONS: Dict[str, List[str]] = {
    # IAM - Service Account Impersonation & Privilege Escalation
    "iam": [
        # Token generation (CRITICAL for impersonation)
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        # Key management (persistence)
        "iam.serviceAccountKeys.create",
        "iam.serviceAccountKeys.get",
        "iam.serviceAccountKeys.list",
        "iam.serviceAccountKeys.delete",
        # Service account enumeration
        "iam.serviceAccounts.list",
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.create",
        "iam.serviceAccounts.delete",
        "iam.serviceAccounts.update",
        # IAM policy manipulation (privilege escalation)
        "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.getIamPolicy",
        # Role management
        "iam.roles.list",
        "iam.roles.get",
        "iam.roles.create",
        "iam.roles.update",
        "iam.roles.delete",
    ],

    # Resource Manager - Project/Org IAM manipulation
    "resourcemanager": [
        # Project IAM (CRITICAL)
        "resourcemanager.projects.get",
        "resourcemanager.projects.list",
        "resourcemanager.projects.getIamPolicy",
        "resourcemanager.projects.setIamPolicy",
        # Organization level
        "resourcemanager.organizations.get",
        "resourcemanager.organizations.getIamPolicy",
        "resourcemanager.organizations.setIamPolicy",
        # Folder level
        "resourcemanager.folders.get",
        "resourcemanager.folders.list",
        "resourcemanager.folders.getIamPolicy",
        "resourcemanager.folders.setIamPolicy",
    ],

    # Compute Engine - Instance access, metadata manipulation
    "compute": [
        # Instance enumeration
        "compute.instances.list",
        "compute.instances.get",
        # Metadata manipulation (SSH keys injection)
        "compute.instances.setMetadata",
        "compute.projects.setCommonInstanceMetadata",
        # Serial console (persistence/access)
        "compute.instances.getSerialPortOutput",
        # Instance control
        "compute.instances.start",
        "compute.instances.stop",
        "compute.instances.reset",
        # OS Login
        "compute.instances.osLogin",
        "compute.instances.osAdminLogin",
        # Disk access
        "compute.disks.list",
        "compute.disks.get",
        "compute.disks.create",
        "compute.disks.createSnapshot",
        # Network
        "compute.firewalls.list",
        "compute.firewalls.create",
        "compute.firewalls.update",
        "compute.firewalls.delete",
    ],

    # Cloud Storage - Data exfiltration
    "storage": [
        "storage.buckets.list",
        "storage.buckets.get",
        "storage.buckets.create",
        "storage.buckets.delete",
        "storage.buckets.update",
        "storage.buckets.getIamPolicy",
        "storage.buckets.setIamPolicy",
        "storage.objects.list",
        "storage.objects.get",
        "storage.objects.create",
        "storage.objects.delete",
        "storage.objects.update",
        "storage.objects.getIamPolicy",
        "storage.objects.setIamPolicy",
        # Managed folders
        "storage.managedFolders.list",
        "storage.managedFolders.get",
        "storage.managedFolders.create",
        "storage.managedFolders.delete",
        "storage.managedFolders.getIamPolicy",
        "storage.managedFolders.setIamPolicy",
        # Multipart uploads
        "storage.multipartUploads.list",
        "storage.multipartUploads.create",
        "storage.multipartUploads.abort",
        "storage.multipartUploads.listParts",
    ],

    # Secret Manager - Credentials extraction
    "secretmanager": [
        "secretmanager.secrets.list",
        "secretmanager.secrets.get",
        "secretmanager.secrets.create",
        "secretmanager.secrets.delete",
        "secretmanager.versions.list",
        "secretmanager.versions.get",
        "secretmanager.versions.access",  # CRITICAL - read secret value
        "secretmanager.versions.add",
        "secretmanager.secrets.getIamPolicy",
        "secretmanager.secrets.setIamPolicy",
    ],

    # Cloud Functions - Code execution
    "cloudfunctions": [
        "cloudfunctions.functions.list",
        "cloudfunctions.functions.get",
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.update",
        "cloudfunctions.functions.delete",
        "cloudfunctions.functions.call",  # Direct invocation (v1)
        "cloudfunctions.functions.invoke",  # Direct invocation (v2)
        "cloudfunctions.functions.getIamPolicy",
        "cloudfunctions.functions.setIamPolicy",
        "cloudfunctions.functions.sourceCodeGet",
        "cloudfunctions.functions.sourceCodeSet",
        # Locations & operations
        "cloudfunctions.locations.list",
        "cloudfunctions.locations.get",
        "cloudfunctions.operations.list",
        "cloudfunctions.operations.get",
        "cloudfunctions.runtimes.list",
    ],

    # Cloud Run - Container execution
    "run": [
        "run.services.list",
        "run.services.get",
        "run.services.create",
        "run.services.update",
        "run.services.delete",
        "run.services.getIamPolicy",
        "run.services.setIamPolicy",
        "run.jobs.list",
        "run.jobs.run",
    ],
}


# =============================================================================
# FULL_PERMISSIONS - Extended coverage of common services
# =============================================================================
FULL_PERMISSIONS: Dict[str, List[str]] = {
    # Include all FAST permissions
    **{k: v[:] for k, v in FAST_PERMISSIONS.items()},

    # Extended IAM
    "iam": FAST_PERMISSIONS["iam"] + [
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.enable",
        "iam.serviceAccounts.disable",
        "iam.serviceAccounts.undelete",
        "iam.roles.undelete",
    ],

    # GKE - Kubernetes cluster access
    "container": [
        "container.clusters.list",
        "container.clusters.get",
        "container.clusters.create",
        "container.clusters.update",
        "container.clusters.delete",
        "container.clusters.getCredentials",
        # Node pools
        "container.nodes.list",
        "container.nodes.get",
        # Pods & workloads
        "container.pods.list",
        "container.pods.get",
        "container.pods.create",
        "container.pods.exec",  # CRITICAL - shell into pods
        "container.pods.portForward",
        # Secrets in K8s
        "container.secrets.list",
        "container.secrets.get",
        "container.secrets.create",
        # RBAC
        "container.clusterRoles.list",
        "container.clusterRoleBindings.list",
        "container.roles.list",
        "container.roleBindings.list",
    ],

    # BigQuery - Data access
    "bigquery": [
        "bigquery.datasets.get",
        "bigquery.datasets.list",
        "bigquery.datasets.create",
        "bigquery.datasets.getIamPolicy",
        "bigquery.datasets.setIamPolicy",
        "bigquery.tables.list",
        "bigquery.tables.get",
        "bigquery.tables.getData",  # CRITICAL - read data
        "bigquery.tables.create",
        "bigquery.tables.export",
        "bigquery.jobs.create",
        "bigquery.jobs.list",
        "bigquery.jobs.get",
    ],

    # Cloud SQL - Database access
    "cloudsql": [
        "cloudsql.instances.list",
        "cloudsql.instances.get",
        "cloudsql.instances.create",
        "cloudsql.instances.delete",
        "cloudsql.instances.connect",
        "cloudsql.instances.login",
        "cloudsql.databases.list",
        "cloudsql.databases.get",
        "cloudsql.databases.create",
        "cloudsql.users.list",
        "cloudsql.users.create",
        "cloudsql.users.update",
        "cloudsql.backupRuns.list",
        "cloudsql.backupRuns.create",
    ],

    # Pub/Sub - Message queues
    "pubsub": [
        "pubsub.topics.list",
        "pubsub.topics.get",
        "pubsub.topics.create",
        "pubsub.topics.publish",
        "pubsub.topics.getIamPolicy",
        "pubsub.topics.setIamPolicy",
        "pubsub.subscriptions.list",
        "pubsub.subscriptions.get",
        "pubsub.subscriptions.create",
        "pubsub.subscriptions.consume",  # Read messages
        "pubsub.subscriptions.getIamPolicy",
        "pubsub.subscriptions.setIamPolicy",
    ],

    # Cloud KMS - Key management
    "cloudkms": [
        "cloudkms.keyRings.list",
        "cloudkms.keyRings.get",
        "cloudkms.keyRings.create",
        "cloudkms.keyRings.getIamPolicy",
        "cloudkms.keyRings.setIamPolicy",
        "cloudkms.cryptoKeys.list",
        "cloudkms.cryptoKeys.get",
        "cloudkms.cryptoKeys.create",
        "cloudkms.cryptoKeys.update",
        "cloudkms.cryptoKeys.getIamPolicy",
        "cloudkms.cryptoKeys.setIamPolicy",
        "cloudkms.cryptoKeyVersions.list",
        "cloudkms.cryptoKeyVersions.useToDecrypt",  # CRITICAL
        "cloudkms.cryptoKeyVersions.useToEncrypt",
        "cloudkms.cryptoKeyVersions.useToSign",
    ],

    # Logging - Audit logs access
    "logging": [
        "logging.logEntries.list",
        "logging.logs.list",
        "logging.logs.delete",  # Cover tracks
        "logging.sinks.list",
        "logging.sinks.get",
        "logging.sinks.create",
        "logging.sinks.update",
        "logging.sinks.delete",
        "logging.privateLogEntries.list",  # Admin activity
    ],

    # Monitoring - Metrics & alerting
    "monitoring": [
        "monitoring.timeSeries.list",
        "monitoring.metricDescriptors.list",
        "monitoring.alertPolicies.list",
        "monitoring.alertPolicies.get",
        "monitoring.alertPolicies.create",
        "monitoring.alertPolicies.update",
        "monitoring.alertPolicies.delete",
    ],

    # Compute - Extended
    "compute": FAST_PERMISSIONS["compute"] + [
        "compute.networks.list",
        "compute.networks.get",
        "compute.networks.create",
        "compute.subnetworks.list",
        "compute.subnetworks.get",
        "compute.images.list",
        "compute.images.get",
        "compute.images.create",
        "compute.snapshots.list",
        "compute.snapshots.get",
        "compute.snapshots.create",
        "compute.instanceTemplates.list",
        "compute.instanceTemplates.get",
        "compute.instanceGroups.list",
        "compute.vpnTunnels.list",
        "compute.routers.list",
    ],

    # Cloud Build - CI/CD
    "cloudbuild": [
        "cloudbuild.builds.list",
        "cloudbuild.builds.get",
        "cloudbuild.builds.create",
        "cloudbuild.workerpools.list",
        "cloudbuild.workerpools.get",
    ],

    # Artifact Registry / Container Registry
    "artifactregistry": [
        "artifactregistry.repositories.list",
        "artifactregistry.repositories.get",
        "artifactregistry.repositories.downloadArtifacts",
        "artifactregistry.repositories.uploadArtifacts",
        "artifactregistry.tags.list",
        "artifactregistry.versions.list",
    ],

    # Service accounts actAs for deployment
    "deploymentmanager": [
        "deploymentmanager.deployments.list",
        "deploymentmanager.deployments.get",
        "deploymentmanager.deployments.create",
        "deploymentmanager.deployments.update",
        "deploymentmanager.deployments.delete",
    ],

    # Parameter Manager - Configuration/secrets storage (similar to Secret Manager)
    "parametermanager": [
        "parametermanager.parameters.list",
        "parametermanager.parameters.get",
        "parametermanager.parameters.create",
        "parametermanager.parameters.update",
        "parametermanager.parameters.delete",
        "parametermanager.parameterVersions.list",
        "parametermanager.parameterVersions.get",
        "parametermanager.parameterVersions.render",  # CRITICAL - read actual value
        "parametermanager.parameterVersions.create",
        "parametermanager.locations.list",
    ],
}


# =============================================================================
# LOW_PERMISSIONS - Less exploitable but comprehensive
# =============================================================================
LOW_PERMISSIONS: Dict[str, List[str]] = {
    # Dataflow
    "dataflow": [
        "dataflow.jobs.list",
        "dataflow.jobs.get",
        "dataflow.jobs.create",
        "dataflow.jobs.cancel",
        "dataflow.jobs.updateContents",
    ],

    # Dataproc - Hadoop/Spark
    "dataproc": [
        "dataproc.clusters.list",
        "dataproc.clusters.get",
        "dataproc.clusters.create",
        "dataproc.clusters.delete",
        "dataproc.jobs.list",
        "dataproc.jobs.get",
        "dataproc.jobs.create",
        "dataproc.jobs.cancel",
    ],

    # App Engine
    "appengine": [
        "appengine.applications.get",
        "appengine.services.list",
        "appengine.services.get",
        "appengine.versions.list",
        "appengine.versions.get",
        "appengine.versions.create",
        "appengine.instances.list",
        "appengine.instances.get",
    ],

    # Cloud DNS
    "dns": [
        "dns.managedZones.list",
        "dns.managedZones.get",
        "dns.managedZones.create",
        "dns.resourceRecordSets.list",
        "dns.resourceRecordSets.get",
        "dns.resourceRecordSets.create",
        "dns.resourceRecordSets.update",
        "dns.resourceRecordSets.delete",
    ],

    # Filestore
    "file": [
        "file.instances.list",
        "file.instances.get",
        "file.instances.create",
        "file.backups.list",
        "file.backups.get",
    ],

    # Memorystore (Redis)
    "redis": [
        "redis.instances.list",
        "redis.instances.get",
        "redis.instances.create",
        "redis.instances.connect",
    ],

    # Spanner
    "spanner": [
        "spanner.instances.list",
        "spanner.instances.get",
        "spanner.instances.create",
        "spanner.databases.list",
        "spanner.databases.get",
        "spanner.databases.create",
        "spanner.sessions.list",
        "spanner.sessions.create",
    ],

    # Bigtable
    "bigtable": [
        "bigtable.instances.list",
        "bigtable.instances.get",
        "bigtable.clusters.list",
        "bigtable.tables.list",
        "bigtable.tables.get",
        "bigtable.tables.readRows",
        "bigtable.tables.mutateRows",
    ],

    # Composer (Airflow)
    "composer": [
        "composer.environments.list",
        "composer.environments.get",
        "composer.environments.create",
    ],

    # Cloud Tasks
    "cloudtasks": [
        "cloudtasks.queues.list",
        "cloudtasks.queues.get",
        "cloudtasks.tasks.list",
        "cloudtasks.tasks.get",
        "cloudtasks.tasks.create",
        "cloudtasks.tasks.run",
    ],

    # Cloud Scheduler
    "cloudscheduler": [
        "cloudscheduler.jobs.list",
        "cloudscheduler.jobs.get",
        "cloudscheduler.jobs.create",
        "cloudscheduler.jobs.run",
        "cloudscheduler.jobs.delete",
    ],

    # Endpoints
    "servicemanagement": [
        "servicemanagement.services.list",
        "servicemanagement.services.get",
    ],

    # Service Usage
    "serviceusage": [
        "serviceusage.services.list",
        "serviceusage.services.get",
        "serviceusage.services.enable",
        "serviceusage.services.disable",
    ],

    # Binary Authorization
    "binaryauthorization": [
        "binaryauthorization.policy.get",
        "binaryauthorization.policy.update",
        "binaryauthorization.attestors.list",
        "binaryauthorization.attestors.get",
    ],

    # VPC Service Controls
    "accesscontextmanager": [
        "accesscontextmanager.accessPolicies.list",
        "accesscontextmanager.accessPolicies.get",
        "accesscontextmanager.accessLevels.list",
        "accesscontextmanager.servicePerimeters.list",
    ],

    # Billing
    "billing": [
        "billing.accounts.list",
        "billing.accounts.get",
        "billing.budgets.list",
        "billing.budgets.get",
    ],

    # Network Services
    "networkservices": [
        "networkservices.meshes.list",
        "networkservices.gateways.list",
        "networkservices.httpRoutes.list",
    ],

    # Security Command Center
    "securitycenter": [
        "securitycenter.assets.list",
        "securitycenter.findings.list",
        "securitycenter.findings.update",
        "securitycenter.sources.list",
    ],

    # Web Security Scanner
    "websecurityscanner": [
        "websecurityscanner.scanconfigs.list",
        "websecurityscanner.scanruns.list",
        "websecurityscanner.results.list",
    ],

    # Recommender
    "recommender": [
        "recommender.iamPolicyRecommendations.list",
        "recommender.iamPolicyRecommendations.get",
        "recommender.iamServiceAccountInsights.list",
    ],

    # OS Config
    "osconfig": [
        "osconfig.patchJobs.list",
        "osconfig.patchDeployments.list",
        "osconfig.inventories.list",
        "osconfig.vulnerabilityReports.list",
    ],

    # OAuth Configuration (OAuth consent screen, client IDs)
    "clientauthconfig": [
        "clientauthconfig.brands.list",
        "clientauthconfig.brands.get",
        "clientauthconfig.brands.create",
        "clientauthconfig.brands.update",
        "clientauthconfig.clients.list",
        "clientauthconfig.clients.get",
        "clientauthconfig.clients.create",
        "clientauthconfig.clients.update",
        "clientauthconfig.clients.delete",
        "clientauthconfig.clients.listWithSecrets",  # Get client secrets
    ],
}


# =============================================================================
# Dangerous permissions - highlighted in output
# =============================================================================
DANGEROUS_PERMISSIONS: List[str] = [
    # Token/Impersonation
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.actAs",
    # Key creation (persistence)
    "iam.serviceAccountKeys.create",
    # IAM policy manipulation
    "iam.serviceAccounts.setIamPolicy",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "storage.buckets.setIamPolicy",
    "secretmanager.secrets.setIamPolicy",
    "bigquery.datasets.setIamPolicy",
    "pubsub.topics.setIamPolicy",
    "pubsub.subscriptions.setIamPolicy",
    "cloudkms.keyRings.setIamPolicy",
    "cloudkms.cryptoKeys.setIamPolicy",
    "cloudfunctions.functions.setIamPolicy",
    "run.services.setIamPolicy",
    # Secret/Parameter access
    "secretmanager.versions.access",
    "parametermanager.parameterVersions.render",
    # Data access
    "bigquery.tables.getData",
    "storage.objects.get",
    # Code execution
    "cloudfunctions.functions.call",
    "cloudfunctions.functions.invoke",
    "cloudfunctions.functions.update",
    "cloudfunctions.functions.sourceCodeSet",
    "run.services.update",
    "container.pods.exec",
    # Metadata manipulation (SSH keys)
    "compute.instances.setMetadata",
    "compute.projects.setCommonInstanceMetadata",
    # Admin access
    "compute.instances.osAdminLogin",
    # Decryption
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    # Log deletion (anti-forensics)
    "logging.logs.delete",
    # Role creation
    "iam.roles.create",
    "iam.roles.update",
]


def get_gcp_profile_permissions(mode: str) -> Dict[str, List[str]]:
    """
    Returns permission profile based on mode:
      - "fast" (default): FAST_PERMISSIONS - high-value exploitable permissions
      - "full": FULL_PERMISSIONS - extended common services coverage
      - "low": LOW_PERMISSIONS - less exploitable but comprehensive
    """
    mode = mode.lower()
    if mode == "full":
        return FULL_PERMISSIONS
    elif mode == "low":
        return LOW_PERMISSIONS
    return FAST_PERMISSIONS


def is_dangerous_permission(permission: str) -> bool:
    """Check if a permission is considered dangerous for privilege escalation."""
    return permission in DANGEROUS_PERMISSIONS
