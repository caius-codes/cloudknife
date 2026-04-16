"""
Azure Graph API Permission Bruteforce Module.

Enumerates Graph API permissions by making actual API calls and analyzing responses.
Similar to AWS and GCP IAM bruteforce modules.

Unlike GCP (which has testIamPermissions API), Azure requires actual API calls
to determine permissions. We use minimal read operations and fake resource IDs
for write permissions to avoid modifying real data.

Usage:
    bruteforce_graph_permissions         # Fast mode (default) - key permissions
"""

import base64
import json
import time
from typing import Dict, List, Any, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ...azure_session import AzureSessionManager

console = Console()


# =============================================================================
# Graph API Permission Mappings
# Format: "permission_name": ("method", "url", optional_data)
# =============================================================================

# Fast mode: ~30 key permissions covering main categories
FAST_PERMISSIONS_MAPPING: Dict[str, Tuple[str, str, Optional[Dict]]] = {
    # ========== Users & Directory ==========
    "User.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=id,displayName",
        None
    ),
    "User.ReadBasic.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=id,displayName",
        None
    ),
    "User.ReadWrite.All": (
        "PATCH",
        "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000",
        {"displayName": "test"}
    ),
    "Directory.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/directoryObjects?$top=1",
        None
    ),
    "Directory.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/users",
        {"accountEnabled": True, "displayName": "test"}
    ),

    # ========== Groups ==========
    "Group.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/groups?$top=1&$select=id,displayName",
        None
    ),
    "Group.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/groups",
        {"displayName": "test", "mailEnabled": False, "securityEnabled": True}
    ),
    "GroupMember.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/groups?$top=1",
        None
    ),

    # ========== Mail ==========
    "Mail.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/messages?$top=1&$select=id,subject",
        None
    ),
    "Mail.ReadWrite": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/mailFolders",
        None
    ),
    "Mail.Send": (
        "POST",
        "https://graph.microsoft.com/v1.0/me/sendMail",
        {"message": {"subject": "test"}}
    ),

    # ========== Calendar ==========
    "Calendars.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/calendar",
        None
    ),
    "Calendars.ReadWrite": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/calendars",
        None
    ),

    # ========== Files & SharePoint ==========
    "Files.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/drive/root",
        None
    ),
    "Files.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/drive",
        None
    ),
    "Sites.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/sites?$top=1",
        None
    ),
    "Sites.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/sites?search=*&$top=1",
        None
    ),

    # ========== Teams ==========
    "Team.ReadBasic.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/teams?$top=1",
        None
    ),
    "Channel.ReadBasic.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/teams?$top=1",
        None
    ),
    "ChannelMessage.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/teams/00000000-0000-0000-0000-000000000000/channels",
        None
    ),

    # ========== Applications & Service Principals ==========
    "Application.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/applications?$top=1&$select=id,displayName",
        None
    ),
    "Application.ReadWrite.All": (
        "PATCH",
        "https://graph.microsoft.com/v1.0/applications/00000000-0000-0000-0000-000000000000",
        {"displayName": "test"}
    ),
    "AppRoleAssignment.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1",
        None
    ),

    # ========== Roles & Privileged Access ==========
    "RoleManagement.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName",
        None
    ),
    "RoleManagement.Read.Directory": (
        "GET",
        "https://graph.microsoft.com/v1.0/directoryRoles",
        None
    ),
    "RoleManagement.ReadWrite.Directory": (
        "POST",
        "https://graph.microsoft.com/v1.0/directoryRoles/00000000-0000-0000-0000-000000000000/members/$ref",
        {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/00000000-0000-0000-0000-000000000000"}
    ),

    # ========== Policies & Security ==========
    "Policy.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
        None
    ),
    "Policy.ReadWrite.ConditionalAccess": (
        "GET",
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
        None
    ),
    "AuditLog.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1",
        None
    ),
    "SecurityEvents.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/security/alerts?$top=1",
        None
    ),
    "Reports.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='D7')",
        None
    ),
}

# Full mode: ~90 permissions total (FAST + additional)
# Includes all FAST permissions plus extended coverage
FULL_PERMISSIONS_MAPPING: Dict[str, Tuple[str, str, Optional[Dict]]] = {
    **FAST_PERMISSIONS_MAPPING,  # Include all fast permissions
    
    # ========== Users & Directory (Extended) ==========
    "User.Invite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/invitations",
        {"invitedUserEmailAddress": "test@invalid.local", "inviteRedirectUrl": "https://test.local"}
    ),
    "User.ManageIdentities.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=identities",
        None
    ),
    "Directory.AccessAsUser.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/me",
        None
    ),
    "Organization.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/organization",
        None
    ),
    "Domain.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/domains",
        None
    ),

    # ========== Groups (Extended) ==========
    "GroupMember.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/groups/00000000-0000-0000-0000-000000000000/members/$ref",
        {"@odata.id": "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000"}
    ),
    "Group.Create": (
        "POST",
        "https://graph.microsoft.com/v1.0/groups",
        {"displayName": "test", "mailEnabled": False, "mailNickname": "test", "securityEnabled": True}
    ),

    # ========== Mail & Calendar (Extended) ==========
    "Mail.ReadBasic": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/messages?$top=1&$select=id,subject,from",
        None
    ),
    "Mail.ReadBasic.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=id",
        None
    ),
    "Contacts.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/contacts?$top=1",
        None
    ),
    "Contacts.ReadWrite": (
        "POST",
        "https://graph.microsoft.com/v1.0/me/contacts",
        {"givenName": "test"}
    ),
    "MailboxSettings.ReadWrite": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/mailboxSettings",
        None
    ),
    "Calendars.Read.Shared": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/calendarGroups",
        None
    ),

    # ========== Files & SharePoint (Extended) ==========
    "Files.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/drive",
        None
    ),
    "Files.ReadWrite": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/drive/root/children",
        None
    ),
    "Sites.Manage.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/sites?$top=1",
        None
    ),
    "Sites.FullControl.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/sites/root",
        None
    ),

    # ========== Teams (Extended) ==========
    "TeamMember.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$top=1",
        None
    ),
    "TeamMember.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/teams/00000000-0000-0000-0000-000000000000/members",
        {"@odata.type": "#microsoft.graph.aadUserConversationMember"}
    ),
    "TeamSettings.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/teams?$top=1&$select=id",
        None
    ),
    "TeamSettings.ReadWrite.All": (
        "PATCH",
        "https://graph.microsoft.com/v1.0/teams/00000000-0000-0000-0000-000000000000",
        {"memberSettings": {"allowCreateUpdateChannels": True}}
    ),
    "Channel.Create": (
        "POST",
        "https://graph.microsoft.com/v1.0/teams/00000000-0000-0000-0000-000000000000/channels",
        {"displayName": "test"}
    ),
    "ChannelSettings.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/teams?$top=1",
        None
    ),

    # ========== Applications (Extended) ==========
    "Application.ReadWrite.OwnedBy": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/ownedObjects?$top=1",
        None
    ),
    "ServicePrincipalEndpoint.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1&$select=id,servicePrincipalNames",
        None
    ),
    "DelegatedPermissionGrant.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=1",
        None
    ),
    "AppCatalog.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/appCatalogs/teamsApps?$top=1",
        None
    ),

    # ========== Roles & Privileged Access (Extended) ==========
    "PrivilegedAccess.Read.AzureAD": (
        "GET",
        "https://graph.microsoft.com/v1.0/privilegedAccess/azureResources/resources?$top=1",
        None
    ),
    "PrivilegedAccess.ReadWrite.AzureAD": (
        "POST",
        "https://graph.microsoft.com/v1.0/privilegedAccess/azureResources/roleAssignmentRequests",
        {"roleDefinitionId": "00000000-0000-0000-0000-000000000000"}
    ),
    "RoleManagementPolicy.Read.Directory": (
        "GET",
        "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$top=1",
        None
    ),
    "PrivilegedEligibilitySchedule.Read.AzureADGroup": (
        "GET",
        "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?$top=1",
        None
    ),
    "DirectoryRecommendations.Read.All": (
        "GET",
        "https://graph.microsoft.com/beta/directory/recommendations?$top=1",
        None
    ),

    # ========== Policies & Security (Extended) ==========
    "Policy.ReadWrite.AuthenticationMethod": (
        "GET",
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy",
        None
    ),
    "Policy.ReadWrite.Authorization": (
        "GET",
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
        None
    ),
    "IdentityRiskEvent.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$top=1",
        None
    ),
    "IdentityRiskyUser.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top=1",
        None
    ),
    "ThreatAssessment.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/informationProtection/threatAssessmentRequests?$top=1",
        None
    ),
    "SecurityActions.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/security/securityActions?$top=1",
        None
    ),

    # ========== Devices & Intune ==========
    "Device.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/devices?$top=1&$select=id,displayName",
        None
    ),
    "Device.ReadWrite.All": (
        "PATCH",
        "https://graph.microsoft.com/v1.0/devices/00000000-0000-0000-0000-000000000000",
        {"accountEnabled": True}
    ),
    "DeviceManagementConfiguration.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$top=1",
        None
    ),
    "DeviceManagementConfiguration.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations",
        {"@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration", "displayName": "test"}
    ),
    "DeviceManagementManagedDevices.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
        None
    ),
    "DeviceManagementApps.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?$top=1",
        None
    ),
    "DeviceManagementRBAC.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions?$top=1",
        None
    ),

    # ========== Identity & Governance ==========
    "IdentityProvider.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/identity/identityProviders?$top=1",
        None
    ),
    "IdentityProvider.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/identity/identityProviders",
        {"@odata.type": "microsoft.graph.socialIdentityProvider", "displayName": "test"}
    ),
    "AccessReview.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=1",
        None
    ),
    "AccessReview.ReadWrite.All": (
        "POST",
        "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions",
        {"displayName": "test"}
    ),
    "EntitlementManagement.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$top=1",
        None
    ),

    # ========== People & Presence ==========
    "People.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/people?$top=1",
        None
    ),
    "People.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=id",
        None
    ),
    "Presence.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/me/presence",
        None
    ),
    "Presence.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/communications/presences?$top=1",
        None
    ),

    # ========== Compliance & eDiscovery ==========
    "eDiscovery.Read.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases?$top=1",
        None
    ),
    "InformationProtectionPolicy.Read": (
        "GET",
        "https://graph.microsoft.com/v1.0/informationProtection/policy/labels?$top=1",
        None
    ),
    "ThreatIndicators.ReadWrite.OwnedBy": (
        "GET",
        "https://graph.microsoft.com/v1.0/security/tiIndicators?$top=1",
        None
    ),
    "SecurityEvents.ReadWrite.All": (
        "GET",
        "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1",
        None
    ),
}


# Dangerous permissions that enable privilege escalation
DANGEROUS_PERMISSIONS = {
    # Core dangerous permissions (fast mode)
    "RoleManagement.ReadWrite.Directory": "Add users to admin roles → full tenant control",
    "Application.ReadWrite.All": "Add secrets to apps → steal app credentials",
    "Directory.ReadWrite.All": "Create/delete users → full directory control",
    "User.ReadWrite.All": "Modify any user → password reset, disable MFA",
    "AppRoleAssignment.ReadWrite.All": "Grant permissions to apps → privilege escalation",
    "Policy.ReadWrite.ConditionalAccess": "Modify CA policies → bypass security controls",

    # Additional dangerous permissions (full mode)
    "PrivilegedAccess.ReadWrite.AzureAD": "Manage PIM assignments → escalate to Global Admin",
    "DelegatedPermissionGrant.ReadWrite.All": "Grant consent to apps → steal tokens",
    "Sites.FullControl.All": "Full control over SharePoint → mass data exfiltration",
    "Device.ReadWrite.All": "Manage devices → deploy malware via Intune",
    "DeviceManagementConfiguration.ReadWrite.All": "Manage Intune config → compromise endpoints",
    "IdentityProvider.ReadWrite.All": "Add federated IdP → backdoor authentication",
    "Policy.ReadWrite.AuthenticationMethod": "Disable MFA → bypass all security",
    "AccessReview.ReadWrite.All": "Approve own access → maintain persistence",
    "GroupMember.ReadWrite.All": "Add to privileged groups → privilege escalation",
    "User.Invite.All": "Invite external users → expand attack surface",
}


# Category mapping for organization
PERMISSION_CATEGORIES = {
    # Users & Directory
    "User.Read.All": "Users & Directory",
    "User.ReadBasic.All": "Users & Directory",
    "User.ReadWrite.All": "Users & Directory",
    "Directory.Read.All": "Users & Directory",
    "Directory.ReadWrite.All": "Users & Directory",

    # Groups
    "Group.Read.All": "Groups",
    "Group.ReadWrite.All": "Groups",
    "GroupMember.Read.All": "Groups",

    # Mail
    "Mail.Read": "Mail & Calendar",
    "Mail.ReadWrite": "Mail & Calendar",
    "Mail.Send": "Mail & Calendar",
    "Calendars.Read": "Mail & Calendar",
    "Calendars.ReadWrite": "Mail & Calendar",

    # Files
    "Files.Read.All": "Files & SharePoint",
    "Files.ReadWrite.All": "Files & SharePoint",
    "Sites.Read.All": "Files & SharePoint",
    "Sites.ReadWrite.All": "Files & SharePoint",

    # Teams
    "Team.ReadBasic.All": "Teams",
    "Channel.ReadBasic.All": "Teams",
    "ChannelMessage.Read.All": "Teams",

    # Applications
    "Application.Read.All": "Applications",
    "Application.ReadWrite.All": "Applications",
    "AppRoleAssignment.ReadWrite.All": "Applications",

    # Roles
    "RoleManagement.Read.All": "Roles & Security",
    "RoleManagement.Read.Directory": "Roles & Security",
    "RoleManagement.ReadWrite.Directory": "Roles & Security",

    # Policies
    "Policy.Read.All": "Policies & Audit",
    "Policy.ReadWrite.ConditionalAccess": "Policies & Audit",
    "AuditLog.Read.All": "Policies & Audit",
    "SecurityEvents.Read.All": "Policies & Audit",
    "Reports.Read.All": "Policies & Audit",
    # Users & Directory (Extended)
    "User.Invite.All": "Users & Directory",
    "User.ManageIdentities.All": "Users & Directory",
    "Directory.AccessAsUser.All": "Users & Directory",
    "Organization.Read.All": "Users & Directory",
    "Domain.Read.All": "Users & Directory",

    # Groups (Extended)
    "GroupMember.ReadWrite.All": "Groups",
    "Group.Create": "Groups",

    # Mail & Calendar (Extended)
    "Mail.ReadBasic": "Mail & Calendar",
    "Mail.ReadBasic.All": "Mail & Calendar",
    "Contacts.Read": "Mail & Calendar",
    "Contacts.ReadWrite": "Mail & Calendar",
    "MailboxSettings.ReadWrite": "Mail & Calendar",
    "Calendars.Read.Shared": "Mail & Calendar",

    # Files & SharePoint (Extended)
    "Files.Read": "Files & SharePoint",
    "Files.ReadWrite": "Files & SharePoint",
    "Sites.Manage.All": "Files & SharePoint",
    "Sites.FullControl.All": "Files & SharePoint",

    # Teams (Extended)
    "TeamMember.Read.All": "Teams",
    "TeamMember.ReadWrite.All": "Teams",
    "TeamSettings.Read.All": "Teams",
    "TeamSettings.ReadWrite.All": "Teams",
    "Channel.Create": "Teams",
    "ChannelSettings.Read.All": "Teams",

    # Applications (Extended)
    "Application.ReadWrite.OwnedBy": "Applications",
    "ServicePrincipalEndpoint.Read.All": "Applications",
    "DelegatedPermissionGrant.ReadWrite.All": "Applications",
    "AppCatalog.Read.All": "Applications",

    # Roles & Security (Extended)
    "PrivilegedAccess.Read.AzureAD": "Roles & Security",
    "PrivilegedAccess.ReadWrite.AzureAD": "Roles & Security",
    "RoleManagementPolicy.Read.Directory": "Roles & Security",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup": "Roles & Security",
    "DirectoryRecommendations.Read.All": "Roles & Security",

    # Policies & Audit (Extended)
    "Policy.ReadWrite.AuthenticationMethod": "Policies & Audit",
    "Policy.ReadWrite.Authorization": "Policies & Audit",
    "IdentityRiskEvent.Read.All": "Policies & Audit",
    "IdentityRiskyUser.Read.All": "Policies & Audit",
    "ThreatAssessment.ReadWrite.All": "Policies & Audit",
    "SecurityActions.ReadWrite.All": "Policies & Audit",

    # NEW: Devices & Intune
    "Device.Read.All": "Devices & Intune",
    "Device.ReadWrite.All": "Devices & Intune",
    "DeviceManagementConfiguration.Read.All": "Devices & Intune",
    "DeviceManagementConfiguration.ReadWrite.All": "Devices & Intune",
    "DeviceManagementManagedDevices.Read.All": "Devices & Intune",
    "DeviceManagementApps.Read.All": "Devices & Intune",
    "DeviceManagementRBAC.Read.All": "Devices & Intune",

    # NEW: Identity & Governance
    "IdentityProvider.Read.All": "Identity & Governance",
    "IdentityProvider.ReadWrite.All": "Identity & Governance",
    "AccessReview.Read.All": "Identity & Governance",
    "AccessReview.ReadWrite.All": "Identity & Governance",
    "EntitlementManagement.Read.All": "Identity & Governance",

    # NEW: People & Presence
    "People.Read": "People & Presence",
    "People.Read.All": "People & Presence",
    "Presence.Read": "People & Presence",
    "Presence.Read.All": "People & Presence",

    # NEW: Compliance & eDiscovery
    "eDiscovery.Read.All": "Compliance & eDiscovery",
    "InformationProtectionPolicy.Read": "Compliance & eDiscovery",
    "ThreatIndicators.ReadWrite.OwnedBy": "Compliance & eDiscovery",
    "SecurityEvents.ReadWrite.All": "Compliance & eDiscovery",
}

def _decode_token_scopes(access_token: str) -> Dict[str, List[str]]:
    """
    Decode JWT access token to extract declared scopes/roles.

    This provides a baseline of what the token CLAIMS to have,
    but actual permissions may differ due to Conditional Access, PIM, etc.

    Args:
        access_token: JWT access token

    Returns:
        Dict with "delegated" and "application" scope lists
    """
    try:
        # JWT format: header.payload.signature
        parts = access_token.split('.')
        if len(parts) != 3:
            console.print("[yellow]Invalid token format. Cannot decode scopes.[/yellow]")
            return {"delegated": [], "application": []}

        # Decode payload (second part)
        payload = parts[1]

        # Add padding if needed (JWT base64 omits padding)
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        # Decode base64
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)

        # Extract scopes
        delegated_scopes = []
        application_scopes = []

        # Delegated permissions (user context) - in 'scp' claim, space-separated
        if 'scp' in claims:
            delegated_scopes = claims['scp'].split(' ')

        # Application permissions (app-only context) - in 'roles' claim, list
        if 'roles' in claims:
            application_scopes = claims['roles']

        return {
            "delegated": delegated_scopes,
            "application": application_scopes
        }

    except Exception as e:
        console.print(f"[dim]Could not decode token: {e}[/dim]")
        return {"delegated": [], "application": []}


def _test_graph_permission(
    access_token: str,
    permission: str,
    method: str,
    url: str,
    data: Optional[Dict] = None,
    retry_count: int = 0,
    timeout: int = 10
) -> Tuple[str, str, str]:
    """
    Test a single Graph API permission by making an actual API call.

    Args:
        access_token: Valid Graph API access token
        permission: Permission name (e.g., "User.Read.All")
        method: HTTP method (GET, POST, PATCH, DELETE)
        url: Graph API endpoint URL
        data: Optional JSON data for POST/PATCH
        retry_count: Number of retries for rate limiting (internal)
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Tuple of (permission, status, error_message)
        status: "ALLOWED", "DENIED", "ERROR", "SKIPPED"
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=timeout)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=data, timeout=timeout)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=timeout)
        else:
            return (permission, "ERROR", f"Unsupported method: {method}")

        # Success - permission is granted
        if response.status_code in [200, 201, 204]:
            return (permission, "ALLOWED", "")

        # 404 Not Found - ambiguous for write operations on fake IDs
        # For write operations (PATCH, POST, DELETE), a 404 doesn't prove we have permission
        # The API might return 404 even without write permission
        elif response.status_code == 404:
            # For write operations on fake IDs, mark as UNCERTAIN (likely false positive)
            if method in ["PATCH", "POST", "DELETE"]:
                return (permission, "UNCERTAIN", "Resource not found (write permission unclear - likely false positive)")
            else:
                # For read operations, 404 means we can query but resource doesn't exist
                return (permission, "ALLOWED", "Resource not found (read permission OK)")

        # 403 Forbidden - permission denied
        elif response.status_code == 403:
            try:
                error_data = response.json()
                error_msg = error_data.get("error", {}).get("message", "Forbidden")

                # Check if it's specifically a permission error
                if any(x in error_msg.lower() for x in [
                    "insufficient privileges",
                    "access denied",
                    "authorization_requestdenied",
                    "forbidden",
                    "does not have permission"
                ]):
                    return (permission, "DENIED", error_msg[:100])
                else:
                    # Some other 403 reason (might still have permission)
                    return (permission, "DENIED", error_msg[:100])
            except:
                return (permission, "DENIED", "Forbidden")

        # 401 Unauthorized - token issue
        elif response.status_code == 401:
            return (permission, "ERROR", "Token expired or invalid")

        # 400 Bad Request - might be permission issue or malformed request
        elif response.status_code == 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("error", {}).get("message", "Bad Request")

                # If it's about invalid parameters, we likely have permission
                if "invalid" in error_msg.lower() or "required property" in error_msg.lower():
                    return (permission, "ALLOWED", "Bad request but permission seems OK")
                else:
                    return (permission, "DENIED", error_msg[:100])
            except:
                return (permission, "DENIED", "Bad Request")

        # 429 Rate Limited - retry with limit
        elif response.status_code == 429:
            if retry_count >= 2:
                # Max retries reached
                return (permission, "ERROR", "Rate limit exceeded (max retries)")

            retry_after = int(response.headers.get("Retry-After", 5))
            console.print(f"[yellow]Rate limited on {permission}. Waiting {retry_after}s before retry {retry_count + 1}/2...[/yellow]")
            time.sleep(retry_after)
            # Retry with incremented counter
            return _test_graph_permission(access_token, permission, method, url, data, retry_count + 1, timeout)

        # Other errors
        else:
            return (permission, "ERROR", f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        # Timeout - ask user if they want to skip or retry with longer timeout
        console.print(f"\n[yellow]⏱️  Timeout ({timeout}s) testing {permission}[/yellow]")
        console.print(f"[dim]This endpoint may be slow (e.g., Teams API in large tenants)[/dim]")

        choice = Prompt.ask(
            "[cyan]Choose action[/cyan]",
            choices=["retry", "skip"],
            default="skip"
        ).lower()

        if choice == "retry":
            console.print(f"[cyan]Retrying with 30s timeout...[/cyan]")
            return _test_graph_permission(access_token, permission, method, url, data, retry_count, timeout=30)
        else:
            return (permission, "SKIPPED", f"Skipped due to timeout ({timeout}s)")

    except requests.exceptions.RequestException as e:
        return (permission, "ERROR", str(e)[:100])
    except Exception as e:
        return (permission, "ERROR", str(e)[:100])


def bruteforce_graph_permissions(
    session_mgr: AzureSessionManager,
    mode: str = "fast"
) -> Optional[Dict[str, Any]]:
    """
    Enumerate Graph API permissions by making actual API calls.

    This function tests each permission in the wordlist and categorizes
    the response to determine if the permission is granted.

    Args:
        session_mgr: Azure session manager
        mode: Testing mode - "fast" (~31 perms) or "full" (~90 perms)

    Returns:
        Dict with enumeration results or None on error
    """
    # Get Graph API access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API token available. Use 'get_graph_token' or 'login_interactive' first.[/red]")
        return None

    # Validate token audience
    console.print("[dim]Validating token...[/dim]")
    try:
        import base64
        import json as _json
        parts = access_token.split(".")
        if len(parts) == 3:
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload))

            aud = claims.get("aud", "")
            if aud != "https://graph.microsoft.com":
                console.print(f"[bold red]⚠️  Token has wrong audience: {aud}[/bold red]")
                console.print("[yellow]Expected: https://graph.microsoft.com[/yellow]")
                console.print("[cyan]This token won't work with Graph API. Get a Graph token first:[/cyan]")
                console.print("  - get_graph_token (ROPC flow)")
                console.print("  - login_password (ROPC with save)")
                console.print("  - set_token <file> (import Graph token)")
                return None

            # Check expiry
            exp = claims.get("exp")
            if exp:
                import time
                if time.time() > exp:
                    console.print("[bold red]⚠️  Token has expired![/bold red]")
                    console.print("[cyan]Get a fresh token with get_graph_token or login_password[/cyan]")
                    return None

            console.print(f"[green]✓ Token is valid (audience: {aud})[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not validate token: {e}[/yellow]")

    # Validate and select permissions mapping
    mode = mode.lower()
    if mode == "full":
        permissions_mapping = FULL_PERMISSIONS_MAPPING
    elif mode == "fast":
        permissions_mapping = FAST_PERMISSIONS_MAPPING
    else:
        console.print(f"[yellow]Unknown mode '{mode}'. Using 'fast' mode.[/yellow]")
        console.print("[dim]Available modes: fast (~31 permissions), full (~90 permissions)[/dim]")
        mode = "fast"
        permissions_mapping = FAST_PERMISSIONS_MAPPING

    total_permissions = len(permissions_mapping)

    console.print(f"\n[bold blue]🔍 Azure Graph API Permission Bruteforce ({mode} mode)[/bold blue]")
    console.print(f"[dim]Total permissions to test: {total_permissions}[/dim]\n")

    # Phase 1: Decode token to see declared scopes
    console.print("[cyan]Phase 1: Decoding token scopes...[/cyan]")
    token_scopes = _decode_token_scopes(access_token)
    delegated = token_scopes.get("delegated", [])
    application = token_scopes.get("application", [])

    if delegated:
        console.print(f"[dim]  → Token declares (delegated): {', '.join(delegated[:10])}{'...' if len(delegated) > 10 else ''}[/dim]")
    if application:
        console.print(f"[dim]  → Token declares (application): {', '.join(application[:10])}{'...' if len(application) > 10 else ''}[/dim]")
    if not delegated and not application:
        console.print(f"[dim]  → Could not extract scopes from token[/dim]")

    console.print()

    # Phase 2: Test each permission via API calls
    console.print("[cyan]Phase 2: Testing via actual API calls...[/cyan]")

    granted_permissions = []
    denied_permissions = []
    error_permissions = []
    skipped_permissions = []
    uncertain_permissions = []  # Permissions that returned ambiguous results (e.g., 404 on write ops)

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
            "[cyan]Testing permissions...",
            total=total_permissions
        )

        permission_list = list(permissions_mapping.items())
        for idx, (permission, (method, url, data)) in enumerate(permission_list):
            progress.update(task, description=f"[cyan]Testing {permission}")

            perm_name, status, error_msg = _test_graph_permission(
                access_token, permission, method, url, data
            )

            if status == "ALLOWED":
                granted_permissions.append(permission)
            elif status == "DENIED":
                denied_permissions.append(permission)
            elif status == "UNCERTAIN":
                uncertain_permissions.append(permission)
            elif status == "SKIPPED":
                skipped_permissions.append(permission)
            else:  # ERROR
                error_permissions.append(permission)

            progress.advance(task)

            # Add small delay between requests to avoid rate limiting (except for last one)
            if idx < len(permission_list) - 1:
                time.sleep(0.3)

    console.print(f"[dim]  → Found {len(granted_permissions)} granted permissions[/dim]")
    console.print(f"[dim]  → Found {len(denied_permissions)} denied permissions[/dim]")
    console.print(f"[dim]  → Found {len(uncertain_permissions)} uncertain permissions (likely false positives)[/dim]")
    console.print(f"[dim]  → Found {len(error_permissions)} errors[/dim]")
    console.print(f"[dim]  → Found {len(skipped_permissions)} skipped[/dim]\n")

    # Debug: Show first error if all requests failed
    if len(error_permissions) == total_permissions:
        console.print("[bold red]⚠️  All requests resulted in errors![/bold red]")
        console.print("[yellow]This usually means the token is invalid, expired, or has the wrong audience.[/yellow]")
        console.print("[cyan]Check your token with:[/cyan]")
        console.print("  1. whoami - to see token details")
        console.print("  2. set_token - to import a fresh token")
        console.print()

    # Organize results by category
    results_by_category: Dict[str, Dict[str, Any]] = {}
    dangerous_found = []
    dangerous_uncertain = []  # Dangerous permissions that are uncertain (likely false positives)

    for permission in granted_permissions:
        category = PERMISSION_CATEGORIES.get(permission, "Other")

        if category not in results_by_category:
            results_by_category[category] = {
                "granted": [],
                "denied": [],
                "uncertain": [],
                "total": 0
            }

        results_by_category[category]["granted"].append(permission)

        # Check if dangerous
        if permission in DANGEROUS_PERMISSIONS:
            dangerous_found.append(permission)

    for permission in denied_permissions:
        category = PERMISSION_CATEGORIES.get(permission, "Other")

        if category not in results_by_category:
            results_by_category[category] = {
                "granted": [],
                "denied": [],
                "uncertain": [],
                "total": 0
            }

        results_by_category[category]["denied"].append(permission)

    for permission in uncertain_permissions:
        category = PERMISSION_CATEGORIES.get(permission, "Other")

        if category not in results_by_category:
            results_by_category[category] = {
                "granted": [],
                "denied": [],
                "uncertain": [],
                "total": 0
            }

        results_by_category[category]["uncertain"].append(permission)

        # Check if dangerous (these are likely false positives)
        if permission in DANGEROUS_PERMISSIONS:
            dangerous_uncertain.append(permission)

    # Calculate totals
    for category in results_by_category:
        results_by_category[category]["total"] = (
            len(results_by_category[category]["granted"]) +
            len(results_by_category[category]["denied"]) +
            len(results_by_category[category]["uncertain"])
        )

    # Merge with existing results (incremental updates)
    # If fast was run first, then full → add new permissions
    # If full was run first, then fast → keep all permissions from full
    existing_data = session_mgr.get_enumeration_data("graph_permissions_bruteforce")

    if existing_data:
        # Merge permission lists (union of sets to avoid duplicates)
        granted_permissions = list(set(granted_permissions) | set(existing_data.get("granted_permissions", [])))
        denied_permissions = list(set(denied_permissions) | set(existing_data.get("denied_permissions", [])))
        uncertain_permissions = list(set(uncertain_permissions) | set(existing_data.get("uncertain_permissions", [])))
        error_permissions = list(set(error_permissions) | set(existing_data.get("error_permissions", [])))
        skipped_permissions = list(set(skipped_permissions) | set(existing_data.get("skipped_permissions", [])))

        # Recalculate dangerous permissions
        dangerous_found = [p for p in granted_permissions if p in DANGEROUS_PERMISSIONS]
        dangerous_uncertain = [p for p in uncertain_permissions if p in DANGEROUS_PERMISSIONS]

        # Recalculate categories with merged permissions
        results_by_category = {}
        all_tested_perms = granted_permissions + denied_permissions + uncertain_permissions

        for permission in granted_permissions:
            category = PERMISSION_CATEGORIES.get(permission, "Other")
            if category not in results_by_category:
                results_by_category[category] = {"granted": [], "denied": [], "uncertain": [], "total": 0}
            results_by_category[category]["granted"].append(permission)

        for permission in denied_permissions:
            category = PERMISSION_CATEGORIES.get(permission, "Other")
            if category not in results_by_category:
                results_by_category[category] = {"granted": [], "denied": [], "uncertain": [], "total": 0}
            results_by_category[category]["denied"].append(permission)

        for permission in uncertain_permissions:
            category = PERMISSION_CATEGORIES.get(permission, "Other")
            if category not in results_by_category:
                results_by_category[category] = {"granted": [], "denied": [], "uncertain": [], "total": 0}
            results_by_category[category]["uncertain"].append(permission)

        # Calculate totals
        for category in results_by_category:
            results_by_category[category]["total"] = (
                len(results_by_category[category]["granted"]) +
                len(results_by_category[category]["denied"]) +
                len(results_by_category[category]["uncertain"])
            )

        total_permissions = len(all_tested_perms)

        console.print(f"[dim]  → Merged with existing data: now tracking {len(granted_permissions)} granted permissions total[/dim]\n")

    # Save results
    enumeration_results = {
        "mode": mode,
        "total_tested": total_permissions,
        "total_granted": len(granted_permissions),
        "total_denied": len(denied_permissions),
        "total_uncertain": len(uncertain_permissions),
        "total_errors": len(error_permissions),
        "total_skipped": len(skipped_permissions),
        "granted_permissions": granted_permissions,
        "denied_permissions": denied_permissions,
        "uncertain_permissions": uncertain_permissions,
        "error_permissions": error_permissions,
        "skipped_permissions": skipped_permissions,
        "dangerous_found": dangerous_found,
        "dangerous_uncertain": dangerous_uncertain,
        "by_category": results_by_category,
        "token_declared_scopes": token_scopes,
    }

    session_mgr.save_enumeration_data("graph_permissions_bruteforce", enumeration_results)

    # Display results
    _display_results(
        enumeration_results,
        results_by_category,
        granted_permissions,
        uncertain_permissions,
        dangerous_found,
        dangerous_uncertain,
        total_permissions,
        skipped_permissions
    )

    return enumeration_results


def _display_results(
    enumeration_results: Dict[str, Any],
    results_by_category: Dict[str, Dict[str, Any]],
    granted_permissions: List[str],
    uncertain_permissions: List[str],
    dangerous_found: List[str],
    dangerous_uncertain: List[str],
    total_permissions: int,
    skipped_permissions: List[str]
):
    """Display enumeration results in a formatted table."""

    # Summary table
    console.print("[bold blue]📊 Permission Summary[/bold blue]\n")

    summary_table = Table()
    summary_table.add_column("Category", style="cyan", no_wrap=True)
    summary_table.add_column("Total", style="white", justify="right")
    summary_table.add_column("Granted", style="green", justify="right")
    summary_table.add_column("Uncertain", style="yellow", justify="right")
    summary_table.add_column("Denied", style="red", justify="right")
    summary_table.add_column("Rate", style="yellow", justify="right")

    # Sort categories alphabetically
    for category in sorted(results_by_category.keys()):
        cat_data = results_by_category[category]
        total = cat_data["total"]
        granted = len(cat_data["granted"])
        uncertain = len(cat_data["uncertain"])
        denied = len(cat_data["denied"])
        rate = f"{(granted / total * 100):.0f}%" if total > 0 else "0%"

        summary_table.add_row(
            category,
            str(total),
            str(granted),
            str(uncertain),
            str(denied),
            rate
        )

    # Add total row
    total_granted = enumeration_results["total_granted"]
    total_uncertain = enumeration_results["total_uncertain"]
    total_denied = enumeration_results["total_denied"]
    total_rate = f"{(total_granted / total_permissions * 100):.0f}%" if total_permissions > 0 else "0%"

    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_permissions}[/bold]",
        f"[bold green]{total_granted}[/bold green]",
        f"[bold yellow]{total_uncertain}[/bold yellow]",
        f"[bold red]{total_denied}[/bold red]",
        f"[bold]{total_rate}[/bold]"
    )

    console.print(summary_table)
    console.print()

    # Debug: Warn if no permissions found at all
    if total_granted == 0 and total_denied == 0:
        console.print("[bold yellow]⚠️  No results found![/bold yellow]")
        console.print("[dim]Possible causes:[/dim]")
        console.print("  - Token is invalid or expired")
        console.print("  - Token has wrong audience (should be https://graph.microsoft.com)")
        console.print("  - Network connectivity issues")
        console.print("  - All requests timed out")
        console.print()
        console.print("[cyan]Try running 'whoami' to check token validity[/cyan]")
        console.print()

    # Dangerous permissions found
    if dangerous_found:
        console.print(f"[bold red]⚠️  DANGEROUS PERMISSIONS FOUND ({len(dangerous_found)}):[/bold red]")
        for perm in sorted(dangerous_found):
            description = DANGEROUS_PERMISSIONS.get(perm, "")
            console.print(f"  [red]🔥[/red] {perm}")
            if description:
                console.print(f"     [dim]{description}[/dim]")
        console.print()

    # Dangerous UNCERTAIN permissions (likely false positives)
    if dangerous_uncertain:
        console.print(f"[bold yellow]⚠️  DANGEROUS PERMISSIONS (UNCERTAIN - LIKELY FALSE POSITIVES) ({len(dangerous_uncertain)}):[/bold yellow]")
        console.print("[dim]These permissions returned 404 on write operations to fake IDs.[/dim]")
        console.print("[dim]This likely means we DON'T have the permission (the API returned 404 regardless of permission).[/dim]")
        console.print("[dim]Manual verification recommended.[/dim]\n")
        for perm in sorted(dangerous_uncertain):
            description = DANGEROUS_PERMISSIONS.get(perm, "")
            console.print(f"  [yellow]⚠[/yellow] {perm} [yellow](UNCERTAIN - likely false positive)[/yellow]")
            if description:
                console.print(f"     [dim]{description}[/dim]")
        console.print()

    # Granted permissions by category
    if granted_permissions:
        console.print("[bold green]✅ Granted Permissions by Category:[/bold green]\n")
        for category in sorted(results_by_category.keys()):
            granted_list = results_by_category[category]["granted"]
            if granted_list:
                console.print(f"[cyan]{category}[/cyan] ({len(granted_list)}):")
                for perm in sorted(granted_list):
                    if perm in DANGEROUS_PERMISSIONS:
                        console.print(f"  [red]🔥[/red] {perm} [red](DANGEROUS)[/red]")
                    else:
                        console.print(f"  [green]✓[/green] {perm}")
                console.print()
    else:
        console.print("[yellow]No permissions granted.[/yellow]\n")

    # Uncertain permissions by category (likely false positives)
    if uncertain_permissions:
        console.print("[bold yellow]⚠️  Uncertain Permissions by Category (likely false positives):[/bold yellow]\n")
        for category in sorted(results_by_category.keys()):
            uncertain_list = results_by_category[category]["uncertain"]
            if uncertain_list:
                console.print(f"[cyan]{category}[/cyan] ({len(uncertain_list)}):")
                for perm in sorted(uncertain_list):
                    if perm in DANGEROUS_PERMISSIONS:
                        console.print(f"  [yellow]⚠[/yellow] {perm} [yellow](DANGEROUS - likely false positive)[/yellow]")
                    else:
                        console.print(f"  [yellow]⚠[/yellow] {perm} [dim](uncertain)[/dim]")
                console.print()

    # Show skipped permissions if any
    if skipped_permissions:
        console.print(f"\n[yellow]⏭️  Skipped Permissions ({len(skipped_permissions)}):[/yellow]")
        for perm in sorted(skipped_permissions):
            console.print(f"  [dim]•[/dim] {perm} [dim](timeout - endpoint too slow)[/dim]")
        console.print()

    # Summary
    console.print("[green]Results saved under key 'graph_permissions_bruteforce' in session data.[/green]")
    console.print(f"[dim]Total confirmed permissions: {total_granted}[/dim]")
    if len(uncertain_permissions) > 0:
        console.print(f"[dim]Total uncertain permissions (likely false positives): {len(uncertain_permissions)}[/dim]")
    if skipped_permissions:
        console.print(f"[dim]Skipped {len(skipped_permissions)} slow endpoint(s) - re-run to test them again.[/dim]")
