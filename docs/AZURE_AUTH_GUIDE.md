# Azure Authentication Guide for Frontend

This guide explains the recommended order of authentication methods for the CloudKnife web interface.

## Quick Start (Recommended Flow)

### For End Users

```
1. Azure CLI (Simplest)
   ↓ (if Azure CLI not installed)
2. Interactive Browser (Most user-friendly)
   ↓ (if browser unavailable)
3. Password/ROPC (Requires username + password)
```

### For Developers/Automation

```
1. Service Principal (Best for automation)
   ↓ (if no service principal available)
2. Access Token (For testing with stolen tokens)
   ↓ (if working in Azure VM/Container)
3. Managed Identity (Automatic for Azure resources)
```

## Method Comparison

| Method | Complexity | Use Case | Supports MFA | Requires Browser |
|--------|-----------|----------|--------------|------------------|
| **Azure CLI** | ⭐ Easiest | Already logged in via CLI | ✅ Yes | No |
| **Interactive Browser** | ⭐⭐ Easy | First-time login | ✅ Yes | Yes |
| **Password/ROPC** | ⭐⭐⭐ Medium | Testing, ADFS | ❌ No | No |
| **Service Principal** | ⭐⭐⭐ Medium | Automation, CI/CD | N/A | No |
| **Device Code** | ⭐⭐⭐⭐ Advanced | SSH sessions, containers | ✅ Yes | Separate device |
| **Access Token** | ⭐⭐⭐⭐ Advanced | Security testing | N/A | No |
| **Managed Identity** | ⭐⭐⭐⭐⭐ Expert | Azure VMs/Containers only | N/A | No |

## Frontend Implementation Priority

### Phase 1: Essential Methods (MVP)
1. ✅ Azure CLI - Zero-config for users with `az login`
2. ✅ Interactive Browser - Universal fallback
3. ✅ Password/ROPC - Simple form (username + password)

### Phase 2: Advanced Methods
4. ✅ Service Principal - Three-field form (tenant, client ID, secret)
5. ✅ Access Token - Import token from file/paste
6. ⬜ Refresh Token - Token exchange (CloudProwl)

### Phase 3: Specialized Methods
7. ✅ Device Code - Display code + URL
8. ✅ Managed Identity - Auto-detect in Azure environments

## UI Flow Recommendations

### Landing Page (Session Selection)

```
┌─────────────────────────────────────────┐
│  Select or Create Azure Session         │
├─────────────────────────────────────────┤
│  📁 Existing Sessions:                   │
│   ○ azure-prod (tenant: contoso.com)    │
│   ○ azure-dev  (tenant: fabrikam.com)   │
│                                          │
│  ➕ Create New Session                   │
│     Session Name: [________________]     │
│                     [Create]             │
└─────────────────────────────────────────┘
```

### Authentication Method Selection

After creating/selecting a session, show:

```
┌─────────────────────────────────────────┐
│  Choose Authentication Method            │
├─────────────────────────────────────────┤
│                                          │
│  🚀 RECOMMENDED                          │
│  ┌───────────────────────────────────┐  │
│  │ ⚡ Azure CLI                       │  │
│  │ Use existing az login credentials │  │
│  │          [Authenticate]            │  │
│  └───────────────────────────────────┘  │
│                                          │
│  🌐 BROWSER-BASED                        │
│  ┌───────────────────────────────────┐  │
│  │ 🖥️  Interactive Browser            │  │
│  │ Opens browser for sign-in         │  │
│  │          [Sign In]                 │  │
│  └───────────────────────────────────┘  │
│                                          │
│  📝 CREDENTIALS                          │
│  ┌───────────────────────────────────┐  │
│  │ 🔑 Username + Password             │  │
│  │ Email: [___________________]       │  │
│  │ Password: [___________________]    │  │
│  │ Tenant: [___________________]      │  │
│  │          [Login]                   │  │
│  └───────────────────────────────────┘  │
│                                          │
│  🔧 ADVANCED ▼                           │
│  └─ Service Principal                    │
│  └─ Access Token                         │
│  └─ Device Code                          │
│  └─ Managed Identity                     │
└─────────────────────────────────────────┘
```

### Azure CLI Authentication

```
┌─────────────────────────────────────────┐
│  Azure CLI Authentication               │
├─────────────────────────────────────────┤
│                                          │
│  ℹ️  This method uses your existing      │
│     Azure CLI login credentials.         │
│                                          │
│  Prerequisites:                          │
│  ✓ Azure CLI installed                   │
│  ✓ Logged in via 'az login'              │
│                                          │
│  Status: Checking...                     │
│                                          │
│        [Authenticate with Azure CLI]     │
│                                          │
└─────────────────────────────────────────┘
```

**Success:**
```
┌─────────────────────────────────────────┐
│  ✅ Authentication Successful            │
├─────────────────────────────────────────┤
│  Tenant: contoso.onmicrosoft.com         │
│  User: john.doe@contoso.com              │
│  Subscription: Production (12345...)     │
│                                          │
│            [Continue to Dashboard]       │
└─────────────────────────────────────────┘
```

**Error:**
```
┌─────────────────────────────────────────┐
│  ❌ Azure CLI Not Found                  │
├─────────────────────────────────────────┤
│  Azure CLI is not installed or not       │
│  configured properly.                    │
│                                          │
│  Please install it from:                 │
│  https://aka.ms/azure-cli                │
│                                          │
│  Or try a different method:              │
│        [Use Interactive Browser]         │
│        [Use Username + Password]         │
└─────────────────────────────────────────┘
```

### Interactive Browser Authentication

```
┌─────────────────────────────────────────┐
│  Interactive Browser Login              │
├─────────────────────────────────────────┤
│                                          │
│  Tenant ID (optional):                   │
│  [_________________________________]     │
│                                          │
│  ℹ️  Leave blank for auto-detect         │
│                                          │
│        [Open Browser to Sign In]         │
│                                          │
└─────────────────────────────────────────┘
```

**During Authentication:**
```
┌─────────────────────────────────────────┐
│  🌐 Browser Window Opened                │
├─────────────────────────────────────────┤
│                                          │
│  Please complete the sign-in process    │
│  in your browser window.                 │
│                                          │
│  🔄 Waiting for authentication...        │
│                                          │
│  [Cancel]                                │
└─────────────────────────────────────────┘
```

### Password/ROPC Authentication

```
┌─────────────────────────────────────────┐
│  Username + Password Login              │
├─────────────────────────────────────────┤
│                                          │
│  Email / UPN:                            │
│  [_________________________________]     │
│                                          │
│  Password:                               │
│  [_________________________________]     │
│                                          │
│  Tenant ID (optional):                   │
│  [_________________________________]     │
│                                          │
│  ⚠️  Note: This method does not support  │
│     MFA-enabled accounts.                │
│                                          │
│            [Sign In]                     │
│                                          │
└─────────────────────────────────────────┘
```

## Error Handling

### Common Errors and UI Messages

| Error Code | User Message | Suggested Action |
|------------|--------------|------------------|
| `Azure CLI not found` | "Azure CLI is not installed" | Show install link |
| `AADSTS50076` (MFA) | "MFA is required. Please use Interactive Browser login instead." | Redirect to browser method |
| `AADSTS50126` | "Invalid username or password" | Show retry form with error |
| `Token expired` | "Your session has expired. Please sign in again." | Re-authenticate |
| `No subscriptions` | "No Azure subscriptions found for this account" | Show tenant-only mode |

## WebSocket Message Flow

### 1. Azure CLI Authentication

```javascript
// Send authentication request
ws.send({
  type: "module.run",
  payload: {
    module_id: "azure.auth_az_cli",
    params: {}
  }
});

// Listen for response
ws.on("message", (data) => {
  if (data.type === "success") {
    // Authentication successful
    console.log("Tenant:", data.data.tenant_id);
    console.log("User:", data.data.account_name);
    // Redirect to dashboard
  } else if (data.type === "error") {
    // Show error message
    console.error("Auth failed:", data.error);
  }
});
```

### 2. Interactive Browser Authentication

```javascript
// Send authentication request
ws.send({
  type: "module.run",
  payload: {
    module_id: "azure.auth_interactive",
    params: {
      tenant_id: "optional-tenant-id"  // or empty
    }
  }
});

// Show "waiting for browser" UI
showWaitingSpinner("Please complete sign-in in browser...");

// Listen for response (may take 30-60 seconds)
ws.on("message", (data) => {
  hideWaitingSpinner();
  
  if (data.type === "success") {
    // Authentication successful
    showSuccessMessage(`Welcome ${data.data.account_name}!`);
  } else if (data.type === "error") {
    // MFA or other error
    if (data.error.includes("AADSTS50076")) {
      showErrorMessage("MFA is required. This is normal - please try again.");
    } else {
      showErrorMessage(data.error);
    }
  }
});
```

### 3. Password Authentication

```javascript
// Send authentication request
ws.send({
  type: "module.run",
  payload: {
    module_id: "azure.auth_password",
    params: {
      username: "user@domain.com",
      password: "password123",
      tenant_id: "optional-tenant-id"
    }
  }
});

// Listen for response
ws.on("message", (data) => {
  if (data.type === "success") {
    // Authentication successful
    showDashboard(data.data);
  } else if (data.type === "error") {
    // Show friendly error
    if (data.error.includes("ROPC")) {
      showErrorMessage("This account requires MFA. Please use Interactive Browser login instead.");
    } else {
      showErrorMessage("Invalid credentials. Please try again.");
    }
  }
});
```

## Best Practices

### 1. Progressive Enhancement
- Start with simplest method (Azure CLI)
- Fallback to browser if CLI unavailable
- Show advanced methods in collapsed panel

### 2. Error Recovery
- Don't just show error codes - translate to user actions
- Suggest alternative methods on failure
- Keep failed form data (except passwords)

### 3. User Feedback
- Show loading states during authentication
- Display clear success messages with user info
- Provide contextual help for each method

### 4. Security
- Never log passwords or secrets
- Clear password fields after failed attempts
- Warn users about ROPC limitations
- Don't persist sensitive data in localStorage

### 5. Accessibility
- Proper ARIA labels on forms
- Keyboard navigation support
- Screen reader friendly error messages
- Focus management after state changes
