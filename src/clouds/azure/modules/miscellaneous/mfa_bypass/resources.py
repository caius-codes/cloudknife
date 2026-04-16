"""
Known Azure Resources (Audiences) for MFA bypass testing.

Based on FindMeAccess by Ryan McFarland (MIT License)
https://github.com/absolomb/FindMeAccess
"""

RESOURCES = {
    "Azure Graph API": "https://graph.windows.net",
    "Azure Management API": "https://management.azure.com",
    "Azure Data Catalog": "https://datacatalog.azure.com",
    "Azure Key Vault": "https://vault.azure.net",
    "Cloud Webapp Proxy": "https://proxy.cloudwebappproxy.net/registerapp",
    "Database": "https://database.windows.net",
    "Microsoft Graph API": "https://graph.microsoft.com",
    "msmamservice": "https://msmamservice.api.application",
    "Office Management": "https://manage.office.com",
    "Office Apps": "https://officeapps.live.com",
    "OneNote": "https://onenote.com",
    "Outlook": "https://outlook.office365.com",
    "Outlook SDF": "https://outlook-sdf.office.com",
    "Sara": "https://api.diagnostics.office.com",
    "Skype For Business": "https://api.skypeforbusiness.com",
    "Spaces Api": "https://api.spaces.skype.com",
    "Webshell Suite": "https://webshell.suite.office.com",
    "Windows Management API": "https://management.core.windows.net",
    "Yammer": "https://api.yammer.com",
}

# High-priority resources most likely to have MFA gaps (for fast mode)
PRIORITY_RESOURCES = [
    "Microsoft Graph API",
    "Azure Management API",
    "Outlook",
    "Spaces Api",  # Teams
]
