# Azure WebSocket API Documentation

This document describes the Azure session management and authentication APIs available via WebSocket.

## Architecture

Azure authentication in CloudKnife supports multiple methods (ordered by simplicity):

1. **Azure CLI** ⭐ - Uses `az login` credentials (SIMPLEST)
2. **Interactive Browser** ⭐ - Opens browser for login (USER-FRIENDLY)
3. **Password/ROPC** - Username + Password (for testing/ADFS)
4. **Service Principal** - Client ID + Secret (for automation)
5. **Device Code** - Browser-less authentication (for SSH/containers)
6. **Access Token** - Stolen/SSRF tokens (for security testing)
7. **Managed Identity** - For Azure VMs/Containers
8. **Refresh Token** - Token exchange (CloudProwl) [NOT YET IMPLEMENTED]

All methods are implemented in the backend (`azure_handler.py`) and exposed via WebSocket messages.

## Session Management

### List Sessions
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.list_sessions",
    "params": {}
  }
}
```

**Response:**
```json
{
  "type": "azure_session_list",
  "success": true,
  "data": {
    "sessions": [
      {
        "name": "azure-default",
        "session_id": "uuid-here",
        "cloud": "azure",
        "tenant_id": "...",
        "subscription_id": "...",
        "subscription_name": "...",
        "account_name": "user@domain.com",
        "current": true
      }
    ]
  }
}
```

### Create/Load Session
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.create_session",
    "params": {
      "name": "my-azure-session"
    }
  }
}
```

**Response:**
```json
{
  "type": "azure_session_created",
  "success": true,
  "data": {
    "session_name": "my-azure-session",
    "session_id": "uuid-here",
    "tenant_id": "...",
    "subscription_id": "...",
    "subscription_name": "...",
    "account_name": "...",
    "auth_method": "service_principal"
  }
}
```

### Delete Session
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.delete_session",
    "params": {
      "name": "my-azure-session"
    }
  }
}
```

## Authentication Methods

### 1. Azure CLI (Simplest - Recommended)

Uses existing Azure CLI credentials (requires `az login` to be run first).

```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_az_cli",
    "params": {}
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Azure CLI authentication successful",
    "tenant_id": "...",
    "subscription_id": "...",
    "subscription_name": "...",
    "account_name": "user@domain.com",
    "user_info_retrieved": true
  }
}
```

**Prerequisites:**
- Azure CLI must be installed (`az --version`)
- User must be logged in (`az login`)

**Advantages:**
- ✅ No credentials needed in the app
- ✅ Inherits Azure CLI authentication state
- ✅ Works with MFA (already handled by `az login`)
- ✅ Supports SSO profiles

### 2. Interactive Browser Login

Opens a browser window for interactive authentication.

```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_interactive",
    "params": {
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  // optional
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Interactive browser authentication successful",
    "tenant_id": "...",
    "user_info_retrieved": true,
    "subscriptions_retrieved": true,
    "subscription_id": "...",
    "subscription_name": "...",
    "account_name": "user@domain.com"
  }
}
```

**Behavior:**
- Opens default browser for authentication
- Supports MFA automatically
- Uses Azure SDK's InteractiveBrowserCredential
- Works with Conditional Access policies

**Error Response (MFA Required):**
```json
{
  "type": "error",
  "success": false,
  "error": "Authentication failed: MFA required. Details: AADSTS50076..."
}
```

### 3. Service Principal (Client Secret)
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_service_principal",
    "params": {
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "your-secret-here"
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Service principal configured successfully",
    "tenant_id": "...",
    "client_id": "...",
    "user_info_retrieved": true,
    "subscriptions_retrieved": true,
    "subscription_id": "...",
    "subscription_name": "..."
  }
}
```

### 2. Device Code Flow
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_device_code",
    "params": {
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  // optional
    }
  }
}
```

**Note:** This triggers an interactive device code flow. The backend will display a code and URL for the user to visit.

### 3. Password Authentication (ROPC)
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_password",
    "params": {
      "username": "user@domain.com",
      "password": "password123",
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  // optional
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Password authentication configured successfully",
    "username": "user@domain.com",
    "tenant_id": "...",
    "account_name": "...",
    "subscription_id": "...",
    "subscription_name": "..."
  }
}
```

**Error Response (MFA Required):**
```json
{
  "type": "error",
  "success": false,
  "error": "Password authentication failed. Check credentials or ensure ROPC is enabled."
}
```

### 4. Access Token (Stolen/SSRF)
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_access_token",
    "params": {
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Token stored in slot: graph_access_token",
    "scope": "graph",
    "audience": "https://graph.microsoft.com",
    "tenant_id": "...",
    "user": "user@domain.com",
    "object_id": "...",
    "is_expired": false,
    "remaining_minutes": 55,
    "user_info_retrieved": true,
    "warning": "This token cannot be refreshed automatically"
  }
}
```

**Supported Token Audiences:**
- `https://graph.microsoft.com` → Graph API
- `https://management.azure.com/` → Azure Resource Manager
- `https://storage.azure.com/` → Storage
- `https://vault.azure.net` → Key Vault
- `https://api.spaces.skype.com` → Teams
- `https://manage.office.com` → Office 365
- `https://outlook.office365.com` → Outlook/Exchange

### 5. Managed Identity
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.auth_managed_identity",
    "params": {
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  // optional, for user-assigned identity
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Managed identity authentication successful",
    "client_id": "system-assigned",
    "user_info_retrieved": false,
    "note": "Managed identity may lack Graph API permissions"
  }
}
```

## User Information

### Get Current User (whoami)
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.whoami",
    "params": {}
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "session_id": "uuid-here",
    "session_name": "azure-default",
    "auth_method": "service_principal",
    "tenant_id": "...",
    "subscription_id": "...",
    "subscription_name": "...",
    "account_name": "user@domain.com",
    "user_id": "...",
    "user_display_name": "John Doe",
    "user_principal_name": "user@domain.com",
    "user_job_title": "Security Engineer",
    "tokens": [
      {
        "scope": "graph",
        "audience": "https://graph.microsoft.com",
        "is_expired": false,
        "expires_at": 1234567890
      },
      {
        "scope": "management",
        "audience": "https://management.azure.com/",
        "is_expired": false,
        "expires_at": 1234567890
      }
    ]
  }
}
```

## Subscription Management

### Set Active Subscription
```json
{
  "type": "module.run",
  "payload": {
    "module_id": "azure.set_subscription",
    "params": {
      "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "subscription_name": "My Subscription"  // optional
    }
  }
}
```

**Response:**
```json
{
  "type": "success",
  "success": true,
  "data": {
    "message": "Subscription set successfully",
    "subscription_id": "...",
    "subscription_name": "My Subscription"
  }
}
```

## Error Handling

All authentication methods return consistent error responses:

```json
{
  "type": "error",
  "success": false,
  "error": "Detailed error message here"
}
```

**Common Error Scenarios:**

1. **MFA Required (ROPC):**
   - Error: "Password authentication failed. Check credentials or ensure ROPC is enabled."
   - Solution: Use device code or interactive flow instead

2. **Invalid Token:**
   - Error: "Token is expired"
   - Solution: Provide a fresh token

3. **No Session Manager:**
   - Error: "No Azure session manager available"
   - Solution: Internal error, check backend logs

4. **Missing Required Fields:**
   - Error: "tenant_id, client_id, and client_secret are required"
   - Solution: Provide all required parameters

## Token Scopes

The backend automatically detects token audiences and stores them in the correct slots:

| Scope | Token Key | Audience |
|-------|-----------|----------|
| `graph` | `graph_access_token` | `https://graph.microsoft.com` |
| `management` | `management_access_token` | `https://management.azure.com/` |
| `storage` | `storage_access_token` | `https://storage.azure.com/` |
| `vault` | `vault_access_token` | `https://vault.azure.net` |
| `teams` | `teams_access_token` | `https://api.spaces.skype.com` |
| `office` | `office_access_token` | `https://manage.office.com` |
| `outlook` | `outlook_access_token` | `https://outlook.office365.com` |

When using `auth_access_token`, the backend will:
1. Decode the JWT to extract the audience
2. Store the token in the correct scope-specific slot
3. Extract tenant_id, user, and expiry information from the token
4. Return all metadata in the response

## Implementation Notes

1. **Session Persistence:**
   - Sessions are stored in `~/.cloudknife/sessions/azure/`
   - Each session has a JSON file with credentials and metadata
   - Sessions persist across server restarts

2. **Credential Caching:**
   - Azure SDK credentials are cached per session
   - Cache is cleared when switching sessions or calling `clear_credential_cache()`

3. **Token Refresh:**
   - Service Principal, Device Code, Interactive, and Password methods support automatic token refresh
   - Access Token method does NOT support refresh (tokens are used as-is)
   - Refresh Token method (CloudProwl) supports token exchange for service discovery

4. **Thread Safety:**
   - All WebSocket operations are async
   - SDK operations run in ThreadPoolExecutor to avoid blocking the event loop

5. **Error Handling:**
   - All methods catch exceptions and return structured error responses
   - Backend logs detailed errors for debugging
   - User-facing errors are sanitized and actionable
