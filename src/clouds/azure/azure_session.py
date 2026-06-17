# src/clouds/azure/azure_session.py

from pathlib import Path
import json
import os
import subprocess
import base64
import warnings
from typing import Dict, Optional, Any, List
from getpass import getpass
from datetime import datetime, timezone

from rich.console import Console
from rich.prompt import Prompt

# Suppress MSAL security warning about response_mode
# This is a cosmetic warning from MSAL library - functionality is not affected
warnings.filterwarnings(
    "ignore",
    message="response_mode='form_post' is recommended for better security",
    category=UserWarning,
    module="msal.oauth2cli.oauth2"
)

# Azure SDK imports
from azure.core.credentials import TokenCredential, AccessToken
from azure.identity import (
    ClientSecretCredential,
    InteractiveBrowserCredential,
    DeviceCodeCredential,
    UsernamePasswordCredential,
    ManagedIdentityCredential,
    AzureCliCredential,
)

from src.core.session import SessionManager

console = Console()


class AccessTokenCredential(TokenCredential):
    """
    Custom credential class for stolen/SSRF access tokens.
    Does not support token refresh - token is used as-is until expiry.
    """

    def __init__(self, token: str, expires_at: Optional[int] = None):
        """
        Args:
            token: The access token string
            expires_at: Unix timestamp when token expires (optional)
        """
        self._token = token
        self._expires_at = expires_at

    def get_token(self, *scopes: str, **kwargs) -> AccessToken:
        """
        Returns the access token without refresh capability.

        Args:
            *scopes: Token scopes (ignored for pre-acquired tokens)
            **kwargs: Additional keyword arguments

        Returns:
            AccessToken object with token and expiry time
        """
        # If we have an expiry time, return it; otherwise set a far future time
        expires_on = self._expires_at if self._expires_at else 9999999999

        return AccessToken(token=self._token, expires_on=expires_on)


class AzureSessionManager(SessionManager):
    def __init__(self, sessions_dir: str = "sessions/azure"):
        super().__init__(sessions_dir)
        # Cache credential per session to avoid re-authentication
        self._credential_cache: Optional[TokenCredential] = None
        self._cached_auth_method: Optional[str] = None

    # ---------- Implement abstract methods ----------

    def _initialize_session_defaults(self) -> None:
        """Set Azure-specific defaults."""
        self.current_session_data.setdefault("cloud", "azure")
        self.current_session_data.setdefault("default_location", "westeurope")
        self.current_session_data.setdefault("locations", [])

    def _get_session_list_fields(self, data: Dict[str, Any], session_name: str) -> Dict[str, Any]:
        """Return Azure-specific session list fields."""
        return {
            "name": session_name,
            "session_id": data.get("session_id", ""),
            "cloud": data.get("cloud", "azure"),
            "subscription_id": data.get("subscription_id"),
            "subscription_name": data.get("subscription_name"),
            "tenant_id": data.get("tenant_id"),
            "account_name": data.get("account_name"),
            "current": session_name == self.current_session,
        }

    # ---------- Locations handling ----------

    @property
    def default_location(self) -> str:
        return self.current_session_data.get("default_location", "westeurope")

    @property
    def configured_locations(self) -> List[str]:
        return self.current_session_data.get("locations", [])

    def set_locations(self, locations: List[str]) -> None:
        self.current_session_data["locations"] = locations
        self.save_current_session()

    # ---------- Scope Management ----------

    @staticmethod
    def _get_scope_url(scope_name: str) -> str:
        """
        Map scope names to Azure scope URLs.

        Args:
            scope_name: Short name like "graph", "management", "storage", "vault"

        Returns:
            Full scope URL string
        """
        scope_map = {
            "graph": "https://graph.microsoft.com/.default",
            "management": "https://management.azure.com/.default",
            "storage": "https://storage.azure.com/.default",
            "vault": "https://vault.azure.net/.default",
        }
        return scope_map.get(scope_name, scope_name)

    # ---------- Azure SDK Credential Management ----------

    def clear_credential_cache(self) -> None:
        """
        Clear the credential cache to force re-authentication.
        Useful when switching sessions or requiring fresh credentials.

        This clears both in-memory cache and attempts to clear MSAL persistent cache.
        """
        self._credential_cache = None
        self._cached_auth_method = None

        # Also clear MSAL token cache to force fresh browser login
        # MSAL cache is typically stored in ~/.IdentityService/
        try:
            import platform
            cache_dir = None

            system = platform.system()
            if system == "Windows":
                # Windows: %LOCALAPPDATA%\.IdentityService
                local_appdata = os.environ.get("LOCALAPPDATA")
                if local_appdata:
                    cache_dir = Path(local_appdata) / ".IdentityService"
            elif system in ("Darwin", "Linux"):
                # macOS and Linux: ~/.IdentityService
                home = Path.home()
                cache_dir = home / ".IdentityService"

            if cache_dir and cache_dir.exists():
                import shutil
                shutil.rmtree(cache_dir, ignore_errors=True)
                # Recreate the directory to avoid issues
                cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Silently ignore errors - cache clearing is best-effort
            pass

    def _find_token_by_audience(self, required_audiences: List[str]) -> Optional[tuple[str, int]]:
        """
        Search through all available tokens to find one matching the required audience.

        Args:
            required_audiences: List of acceptable audience URLs (e.g., ["https://management.azure.com/", "https://management.azure.com"])

        Returns:
            Tuple of (token, expires_at) if found, None otherwise
        """
        # Iterate through all *_access_token keys in session
        for key in self.current_session_data.keys():
            if not key.endswith("_access_token"):
                continue

            token = self.current_session_data.get(key)
            if not token:
                continue

            try:
                # Decode JWT to extract audience
                parts = token.split('.')
                if len(parts) != 3:
                    continue

                # Decode payload (add padding if needed)
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += '=' * padding

                decoded = base64.urlsafe_b64decode(payload)
                claims = json.loads(decoded)

                # Check if audience matches
                token_aud = claims.get("aud", "")
                if token_aud in required_audiences:
                    # Found matching token!
                    expires_key = key.replace("_access_token", "_token_expires_at")
                    expires_at = self.current_session_data.get(expires_key)
                    return (token, expires_at)

            except Exception:
                # Skip invalid tokens
                continue

        return None

    def get_credential(self, scope: str = "graph") -> Optional[TokenCredential]:
        """
        Get Azure SDK credential object for the current session.

        This method returns a TokenCredential that can be used with Azure SDK clients.
        Supports multiple authentication methods:
        - service_principal: ClientSecretCredential
        - interactive: InteractiveBrowserCredential
        - device_code: DeviceCodeCredential
        - password: UsernamePasswordCredential (ROPC - useful for ADFS)
        - access_token: AccessTokenCredential (stolen tokens)
        - managed_identity: ManagedIdentityCredential

        Credentials are cached to avoid re-authentication on every call.

        Args:
            scope: Token scope ("graph", "management", "storage", "vault")

        Returns:
            TokenCredential object or None if not authenticated
        """
        if not self.current_session_data:
            console.print("[yellow]No active session. Create or load a session first.[/yellow]")
            return None

        auth_method = self.current_session_data.get("auth_method")

        if not auth_method:
            console.print(
                "[yellow]No authentication method configured. "
                "Use one of the authentication commands first.[/yellow]"
            )
            return None

        # Return cached credential if auth method hasn't changed
        if self._credential_cache and self._cached_auth_method == auth_method:
            return self._credential_cache

        try:
            credential = None

            if auth_method == "service_principal":
                credential = ClientSecretCredential(
                    tenant_id=self.current_session_data["tenant_id"],
                    client_id=self.current_session_data["client_id"],
                    client_secret=self.current_session_data["client_secret"],
                )

            elif auth_method == "interactive":
                tenant_id = self.current_session_data.get("tenant_id")
                # Use Azure CLI client ID to bypass Conditional Access policies
                # that whitelist Azure CLI but block other applications.
                # Azure CLI well-known client ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46
                credential = InteractiveBrowserCredential(
                    tenant_id=tenant_id,
                    client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                    disable_automatic_authentication=False,
                )

            elif auth_method == "device_code":
                tenant_id = self.current_session_data.get("tenant_id")
                # Use Azure CLI client ID for consistency and to bypass
                # Conditional Access policies
                credential = DeviceCodeCredential(
                    tenant_id=tenant_id,
                    client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                )

            elif auth_method == "password":
                # ROPC (Resource Owner Password Credentials) flow
                # Useful for ADFS and federated scenarios where device code doesn't work
                tenant_id = self.current_session_data.get("tenant_id")
                username = self.current_session_data.get("username")
                password = self.current_session_data.get("password")

                if not username or not password:
                    console.print("[red]Username or password missing from session.[/red]")
                    return None

                # Use Azure CLI client ID for consistency
                credential = UsernamePasswordCredential(
                    tenant_id=tenant_id,
                    client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                    username=username,
                    password=password,
                )

            elif auth_method == "access_token":
                # Map scope to required audiences
                SCOPE_TO_AUDIENCE = {
                    "graph": ["https://graph.microsoft.com", "https://graph.windows.net"],
                    "management": ["https://management.azure.com/", "https://management.azure.com", "https://management.core.windows.net/"],
                    "storage": ["https://storage.azure.com/"],
                    "vault": ["https://vault.azure.net"],
                    "teams": ["https://api.spaces.skype.com"],
                    "office": ["https://manage.office.com"],
                    "outlook": ["https://outlook.office365.com"],
                }

                # Try scope-specific token first (fast path)
                scope_token_key = f"{scope}_access_token"
                token = self.current_session_data.get(scope_token_key)
                expires_key = f"{scope}_token_expires_at"
                expires_at = self.current_session_data.get(expires_key)

                # If not found, search all tokens by audience (intelligent fallback)
                if not token:
                    required_audiences = SCOPE_TO_AUDIENCE.get(scope, [])
                    if required_audiences:
                        console.print(f"[dim]Searching for token with correct audience...[/dim]")
                        result = self._find_token_by_audience(required_audiences)
                        if result:
                            token, expires_at = result
                            console.print(f"[green]Found token with matching audience for {scope}[/green]")

                if not token:
                    # Show which tokens are available
                    available_scopes = []
                    for key in self.current_session_data.keys():
                        if key.endswith("_access_token") and key != "access_token":
                            scope_name = key.replace("_access_token", "")
                            available_scopes.append(scope_name)

                    console.print(f"[yellow]No access token found for scope '{scope}'.[/yellow]")
                    if available_scopes:
                        console.print(f"[dim]Available tokens: {', '.join(available_scopes)}[/dim]")
                    console.print(f"[cyan]Import a token with:[/cyan] set_token /path/to/{scope}_token.txt")
                    return None

                credential = AccessTokenCredential(
                    token=token,
                    expires_at=expires_at,
                )

            elif auth_method == "managed_identity":
                client_id = self.current_session_data.get("client_id")
                credential = ManagedIdentityCredential(
                    client_id=client_id,
                )

            elif auth_method == "az_cli":
                # Use Azure CLI credential - requires az login to be run first
                # This uses the exact same authentication as Azure CLI
                credential = AzureCliCredential()

            elif auth_method == "mfa_bypass":
                # MFA bypass sessions work like access_token sessions
                # Tokens are stored in scope-specific slots (e.g., management_access_token)
                scope_token_key = f"{scope}_access_token"
                token = self.current_session_data.get(scope_token_key)
                expires_key = f"{scope}_token_expires_at"
                expires_at = self.current_session_data.get(expires_key)

                if not token:
                    # Show which tokens are available
                    available_scopes = []
                    for key in self.current_session_data.keys():
                        if key.endswith("_access_token") and key != "access_token":
                            scope_name = key.replace("_access_token", "")
                            available_scopes.append(scope_name)

                    console.print(f"[yellow]No MFA bypass token found for scope '{scope}'.[/yellow]")
                    if available_scopes:
                        console.print(f"[dim]Available bypass tokens: {', '.join(available_scopes)}[/dim]")
                        console.print(f"[dim]This session was created for: {self.current_session_data.get('mfa_bypass_resource', 'unknown')}[/dim]")
                    console.print(f"[cyan]Tip: Run 'audit_mfa_gaps' again with the resource you need[/cyan]")
                    return None

                credential = AccessTokenCredential(
                    token=token,
                    expires_at=expires_at,
                )

            else:
                console.print(f"[red]Unknown auth method: {auth_method}[/red]")
                return None

            # Cache the credential
            self._credential_cache = credential
            self._cached_auth_method = auth_method
            return credential

        except KeyError as e:
            console.print(f"[red]Missing required credential field: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Error creating credential: {e}[/red]")
            return None

    def get_access_token(self, scope: str = "graph") -> Optional[str]:
        """
        Get access token string for direct REST API calls.

        This method tries multiple approaches to get a valid token:
        1. Check for stored token from Azure CLI (from previous extraction)
        2. Try to get token via SDK credential
        3. If SDK fails (e.g., Conditional Access), automatically fallback to Azure CLI

        Args:
            scope: Token scope ("graph", "management", "storage", "vault")

        Returns:
            Access token string or None
        """
        # Check if we have a stored token for this scope (from Azure CLI)
        stored_token_key = f"{scope}_access_token"
        stored_token = self.current_session_data.get(stored_token_key)
        stored_expires = self.current_session_data.get(f"{scope}_token_expires_at")

        if stored_token and stored_expires:
            import time
            if time.time() < stored_expires:
                # Token is still valid
                return stored_token
            else:
                console.print(f"[dim]Stored {scope} token expired. Refreshing...[/dim]")

        # Try to get token via SDK credential
        credential = self.get_credential(scope)
        if credential:
            try:
                scope_url = self._get_scope_url(scope)
                token_obj = credential.get_token(scope_url)
                # Cache in session so the next call reuses it without reopening the browser
                self.current_session_data[stored_token_key] = token_obj.token
                self.current_session_data[f"{scope}_token_expires_at"] = token_obj.expires_on
                self.save_current_session()
                return token_obj.token
            except Exception as e:
                error_msg = str(e)

                # Check if this is a Conditional Access error
                is_ca_error = (
                    "AADSTS53003" in error_msg or  # Blocked by Conditional Access
                    "AADSTS50076" in error_msg or  # MFA required
                    "AADSTS50079" in error_msg or  # User interaction required
                    "Conditional Access" in error_msg
                )

                if is_ca_error and scope == "graph":
                    # Try to extract token from Azure CLI automatically
                    console.print(f"[yellow]SDK token acquisition blocked by Conditional Access.[/yellow]")
                    console.print(f"[cyan]Attempting automatic fallback to Azure CLI...[/cyan]")

                    if self._auto_extract_graph_token_from_cli():
                        # Token extracted successfully, return it
                        return self.current_session_data.get(stored_token_key)
                    else:
                        console.print(f"[red]Automatic fallback failed.[/red]")
                        console.print(f"[yellow]Hint: Run 'az login' first, then try again.[/yellow]")
                        return None
                else:
                    console.print(f"[red]Error getting access token: {e}[/red]")
                    return None

        # No credential available
        return None

    def get_token_from_az_cli(self, resource: str, silent: bool = False) -> Optional[Dict[str, Any]]:
        """
        Extract access token from Azure CLI for a specific resource.

        This is useful when Conditional Access policies block SDK token acquisition
        but Azure CLI can still get tokens.

        Args:
            resource: Resource URL (e.g., "https://graph.microsoft.com")
            silent: If True, suppress error messages (for automatic fallback)

        Returns:
            Dict with 'accessToken' and 'expiresOn' keys, or None
        """
        import subprocess
        import json

        try:
            result = subprocess.run(
                ["az", "account", "get-access-token", "--resource", resource, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            result.check_returncode()

            token_data = json.loads(result.stdout)
            return token_data

        except FileNotFoundError:
            if not silent:
                console.print("[red]Azure CLI (az) not found. Please install it.[/red]")
            return None
        except subprocess.CalledProcessError as e:
            if not silent:
                console.print(f"[red]Azure CLI command failed: {e.stderr}[/red]")
            return None
        except Exception as e:
            if not silent:
                console.print(f"[red]Failed to get token from Azure CLI: {e}[/red]")
            return None

    def store_graph_token_from_cli(self) -> bool:
        """
        Get Graph API token from Azure CLI and store it in the session.

        This bypasses Conditional Access policies that block SDK token acquisition
        by using the Azure CLI's authentication flow instead.

        Returns:
            True if successful, False otherwise
        """
        console.print("[cyan]Extracting Graph API token from Azure CLI...[/cyan]")

        token_data = self.get_token_from_az_cli("https://graph.microsoft.com")
        if not token_data:
            return False

        access_token = token_data.get("accessToken")
        expires_on = token_data.get("expiresOn")

        if not access_token or not expires_on:
            console.print("[red]Invalid token data from Azure CLI.[/red]")
            return False

        # Parse expiry time (format: "2024-01-01 12:00:00.000000")
        from datetime import datetime
        try:
            # Parse the timestamp and convert to Unix epoch
            if "." in expires_on:
                # Format with microseconds
                dt = datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S.%f")
            else:
                # Format without microseconds
                dt = datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S")

            expires_at = int(dt.timestamp())
        except Exception as e:
            console.print(f"[yellow]Could not parse expiry time: {e}. Using 1 hour default.[/yellow]")
            import time
            expires_at = int(time.time()) + 3600  # 1 hour from now

        # Store in session
        self.current_session_data["graph_access_token"] = access_token
        self.current_session_data["graph_token_expires_at"] = expires_at
        self.save_current_session()

        console.print("[green]Graph API token extracted and stored successfully![/green]")
        console.print(f"[dim]Token expires at: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

        return True

    def get_graph_token_via_ropc(self, username: str, password: str, tenant: str = None) -> bool:
        """
        Get Graph API token using Resource Owner Password Credentials (ROPC) flow.

        Similar to AADInternals' Get-AADIntAccessTokenForMSGraph.
        This authenticates directly with username/password to obtain a Graph API token.

        Note: ROPC has limitations:
        - Does not work with MFA-enabled accounts
        - Does not work with federated accounts (ADFS)
        - Deprecated by Microsoft (but still functional)
        - May bypass some Conditional Access policies

        Args:
            username: User email (e.g., user@domain.com)
            password: User password
            tenant: Tenant ID or None to use "organizations" (default: None)

        Returns:
            True if successful, False otherwise
        """
        import requests

        console.print("[cyan]Authenticating with username/password (ROPC flow)...[/cyan]")

        # Microsoft Office client ID (same as AADInternals uses)
        # This client ID supports ROPC flow
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Use "organizations" if no tenant specified (ROPC doesn't work with /common)
        if not tenant or tenant == "common":
            tenant = "organizations"
            console.print("[dim]Using /organizations endpoint (ROPC requires tenant-specific or /organizations)[/dim]")

        # Token endpoint (v1.0, like AADInternals)
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/token"

        # Prepare request data (v1.0 uses "resource" instead of "scope")
        data = {
            "grant_type": "password",
            "client_id": client_id,
            "resource": "https://graph.microsoft.com",
            "username": username,
            "password": password,
        }

        try:
            response = requests.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30
            )

            # Check for errors
            if response.status_code != 200:
                error_data = response.json()
                error_code = error_data.get("error", "unknown")
                error_desc = error_data.get("error_description", "No description")

                # Friendly error messages
                if "AADSTS9001023" in error_desc:
                    console.print("[red]Authentication failed: /common endpoint not supported for ROPC.[/red]")
                    console.print("[yellow]Provide a specific tenant ID instead.[/yellow]")
                elif "AADSTS50076" in error_desc or "AADSTS50079" in error_desc:
                    console.print("[red]Authentication failed: MFA is required.[/red]")
                    console.print("[yellow]ROPC flow does not support MFA. Try 'login_interactive' instead.[/yellow]")
                elif "AADSTS50126" in error_desc:
                    console.print("[red]Authentication failed: Invalid username or password.[/red]")
                elif "AADSTS50034" in error_desc:
                    console.print("[red]User account not found.[/red]")
                elif "AADSTS50057" in error_desc:
                    console.print("[red]Account is disabled.[/red]")
                elif "AADSTS50055" in error_desc:
                    console.print("[red]Password expired.[/red]")
                elif "AADSTS700016" in error_desc:
                    console.print("[red]Application not found in tenant.[/red]")
                    console.print("[yellow]ROPC may be disabled by your organization.[/yellow]")
                elif "AADSTS65001" in error_desc:
                    console.print("[red]User consent required.[/red]")
                elif "AADSTS90100" in error_desc:
                    console.print("[red]Invalid request parameter.[/red]")
                else:
                    console.print(f"[red]Authentication failed: {error_code}[/red]")
                    console.print(f"[yellow]{error_desc}[/yellow]")

                return False

            # Parse successful response
            token_data = response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in_raw = token_data.get("expires_in", 3600)

            if not access_token:
                console.print("[red]No access token in response.[/red]")
                return False

            # Calculate expiry time (ensure expires_in is an integer)
            import time
            try:
                expires_in = int(expires_in_raw)
            except (ValueError, TypeError):
                console.print("[yellow]Could not parse token expiry, using 1 hour default.[/yellow]")
                expires_in = 3600

            expires_at = int(time.time()) + expires_in

            # Store in session
            self.current_session_data["graph_access_token"] = access_token
            self.current_session_data["graph_token_expires_at"] = expires_at

            # Optionally store refresh token for later use
            if refresh_token:
                self.current_session_data["graph_refresh_token"] = refresh_token

            # Store username for context
            self.current_session_data["ropc_username"] = username

            self.save_current_session()

            from datetime import datetime
            console.print("[green]Successfully authenticated via ROPC flow![/green]")
            console.print(f"[cyan]User:[/cyan] {username}")
            console.print(f"[dim]Token valid until: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

            if refresh_token:
                console.print("[dim]Refresh token saved for automatic renewal.[/dim]")

            return True

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error during authentication: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            # Print traceback for debugging
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False

    def get_teams_token_via_ropc(self, username: str, password: str, tenant: str = None) -> bool:
        """
        Get Teams API token using Resource Owner Password Credentials (ROPC) flow.

        Similar to AADInternals' Get-AADIntAccessTokenForTeams.
        This authenticates directly with username/password to obtain a Teams API token.

        The Teams API (https://api.spaces.skype.com) provides access to:
        - Teams messages and conversations
        - Channel data
        - Meeting information
        - Features not available via Microsoft Graph API

        Note: ROPC has the same limitations as Graph token acquisition.

        Args:
            username: User email (e.g., user@domain.com)
            password: User password
            tenant: Tenant ID or None to use "organizations" (default: None)

        Returns:
            True if successful, False otherwise
        """
        import requests

        console.print("[cyan]Authenticating with username/password for Teams API (ROPC flow)...[/cyan]")

        # Microsoft Office client ID (same as AADInternals uses)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Use "organizations" if no tenant specified
        if not tenant or tenant == "common":
            tenant = "organizations"
            console.print("[dim]Using /organizations endpoint[/dim]")

        # Token endpoint (v1.0)
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/token"

        # Prepare request data - Teams API uses different resource
        data = {
            "grant_type": "password",
            "client_id": client_id,
            "resource": "https://api.spaces.skype.com",  # Teams API resource
            "username": username,
            "password": password,
        }

        try:
            response = requests.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30
            )

            # Check for errors
            if response.status_code != 200:
                error_data = response.json()
                error_code = error_data.get("error", "unknown")
                error_desc = error_data.get("error_description", "No description")

                # Friendly error messages
                if "AADSTS9001023" in error_desc:
                    console.print("[red]Authentication failed: /common endpoint not supported for ROPC.[/red]")
                    console.print("[yellow]Provide a specific tenant ID instead.[/yellow]")
                elif "AADSTS50076" in error_desc or "AADSTS50079" in error_desc:
                    console.print("[red]Authentication failed: MFA is required.[/red]")
                    console.print("[yellow]ROPC flow does not support MFA.[/yellow]")
                elif "AADSTS50126" in error_desc:
                    console.print("[red]Authentication failed: Invalid username or password.[/red]")
                elif "AADSTS50034" in error_desc:
                    console.print("[red]User account not found.[/red]")
                elif "AADSTS50057" in error_desc:
                    console.print("[red]Account is disabled.[/red]")
                elif "AADSTS50055" in error_desc:
                    console.print("[red]Password expired.[/red]")
                elif "AADSTS700016" in error_desc:
                    console.print("[red]Application not found in tenant.[/red]")
                    console.print("[yellow]ROPC may be disabled by your organization.[/yellow]")
                else:
                    console.print(f"[red]Authentication failed: {error_code}[/red]")
                    console.print(f"[yellow]{error_desc}[/yellow]")

                return False

            # Parse successful response
            token_data = response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in_raw = token_data.get("expires_in", 3600)

            if not access_token:
                console.print("[red]No access token in response.[/red]")
                return False

            # Calculate expiry time
            import time
            try:
                expires_in = int(expires_in_raw)
            except (ValueError, TypeError):
                console.print("[yellow]Could not parse token expiry, using 1 hour default.[/yellow]")
                expires_in = 3600

            expires_at = int(time.time()) + expires_in

            # Store in session with teams_ prefix
            self.current_session_data["teams_access_token"] = access_token
            self.current_session_data["teams_token_expires_at"] = expires_at

            # Optionally store refresh token
            if refresh_token:
                self.current_session_data["teams_refresh_token"] = refresh_token

            # Store username for context
            self.current_session_data["teams_ropc_username"] = username

            self.save_current_session()

            from datetime import datetime
            console.print("[green]Successfully authenticated for Teams API via ROPC flow![/green]")
            console.print(f"[cyan]User:[/cyan] {username}")
            console.print(f"[cyan]Resource:[/cyan] https://api.spaces.skype.com")
            console.print(f"[dim]Token valid until: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

            if refresh_token:
                console.print("[dim]Refresh token saved for automatic renewal.[/dim]")

            return True

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error during authentication: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False

    def _auto_extract_graph_token_from_cli(self) -> bool:
        """
        Automatically extract Graph API token from Azure CLI (silent version).

        This is called automatically as a fallback when SDK token acquisition
        fails due to Conditional Access policies. It silently tries to get
        the token from Azure CLI without verbose output.

        Returns:
            True if successful, False otherwise
        """
        # Silently try to get token from Azure CLI (silent=True suppresses errors)
        token_data = self.get_token_from_az_cli("https://graph.microsoft.com", silent=True)
        if not token_data:
            return False

        access_token = token_data.get("accessToken")
        expires_on = token_data.get("expiresOn")

        if not access_token or not expires_on:
            return False

        # Parse expiry time (format: "2024-01-01 12:00:00.000000")
        from datetime import datetime
        try:
            # Parse the timestamp and convert to Unix epoch
            if "." in expires_on:
                # Format with microseconds
                dt = datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S.%f")
            else:
                # Format without microseconds
                dt = datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S")

            expires_at = int(dt.timestamp())
        except Exception:
            # Silently use 1 hour default if parsing fails
            import time
            expires_at = int(time.time()) + 3600  # 1 hour from now

        # Store in session
        self.current_session_data["graph_access_token"] = access_token
        self.current_session_data["graph_token_expires_at"] = expires_at
        self.save_current_session()

        console.print("[green]Successfully extracted Graph token from Azure CLI![/green]")
        console.print(f"[dim]Token valid until: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

        return True

    def auto_get_graph_token(self) -> bool:
        """
        Automatically obtain Graph API token using current authentication method.

        This method reuses existing credentials (similar to PowerShell's Connect-MgGraph
        after Connect-AzAccount) without requiring re-authentication:

        - service_principal: Uses SP credentials to get Graph token
        - interactive/device_code/password: Uses SDK credentials to request Graph scope
        - az_cli: Extracts token from Azure CLI
        - access_token: Checks if we have a Graph token stored
        - refresh_token: Uses refresh token to get Graph access token

        Returns:
            True if Graph token obtained successfully, False otherwise
        """
        if not self.current_session_data:
            console.print("[yellow]No active session. Create or load a session first.[/yellow]")
            return False

        auth_method = self.current_session_data.get("auth_method")

        if not auth_method:
            console.print(
                "[yellow]No authentication configured. "
                "Use one of the login commands first.[/yellow]"
            )
            return False

        console.print(f"[cyan]Attempting to get Graph token using {auth_method} credentials...[/cyan]")

        # Method 1: Try to get token via Azure SDK credential
        if auth_method in ["service_principal", "interactive", "device_code", "password", "managed_identity"]:
            try:
                credential = self.get_credential(scope="graph")
                if credential:
                    # Request Graph scope token
                    token = credential.get_token("https://graph.microsoft.com/.default")

                    if token and token.token:
                        # Store in session
                        import time
                        self.current_session_data["graph_access_token"] = token.token
                        self.current_session_data["graph_token_expires_at"] = token.expires_on
                        self.save_current_session()

                        from datetime import datetime
                        console.print("[green]✓ Graph API token obtained successfully![/green]")
                        console.print(f"[dim]Token expires at: {datetime.fromtimestamp(token.expires_on).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
                        console.print("[dim]You can now use graph_* commands (e.g., graph_mail, graph_teams).[/dim]")
                        return True
            except Exception as e:
                console.print(f"[yellow]Failed to get token via SDK: {e}[/yellow]")
                # Fallback to Azure CLI if SDK fails

        # Method 2: Try Azure CLI (works for az_cli auth or as fallback)
        if auth_method == "az_cli" or auth_method in ["service_principal", "interactive", "device_code"]:
            console.print("[dim]Trying to extract token from Azure CLI...[/dim]")
            if self._auto_extract_graph_token_from_cli():
                console.print("[dim]You can now use graph_* commands (e.g., graph_mail, graph_teams).[/dim]")
                return True

        # Method 3: Check if we already have a Graph token (for access_token auth)
        if auth_method == "access_token":
            graph_token = self.current_session_data.get("graph_access_token")
            if graph_token:
                console.print("[green]✓ Graph token already available in session![/green]")
                console.print("[dim]You can now use graph_* commands (e.g., graph_mail, graph_teams).[/dim]")
                return True
            else:
                console.print("[yellow]No Graph token stored. Use 'set_token' to add a Graph API token.[/yellow]")
                return False

        # Method 4: Use refresh token if available
        if auth_method == "refresh_token":
            refresh_token = self.current_session_data.get("refresh_token")
            if not refresh_token:
                console.print("[red]No refresh token found in session.[/red]")
                return False

            try:
                import requests

                # Token endpoint
                token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

                # Request Graph token using refresh token
                data = {
                    "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI client ID
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "scope": "https://graph.microsoft.com/.default",
                }

                response = requests.post(token_url, data=data, timeout=30)
                response.raise_for_status()

                result = response.json()
                access_token = result.get("access_token")
                expires_in = result.get("expires_in", 3600)

                if access_token:
                    import time
                    from datetime import datetime
                    expires_at = int(time.time()) + expires_in

                    self.current_session_data["graph_access_token"] = access_token
                    self.current_session_data["graph_token_expires_at"] = expires_at
                    self.save_current_session()

                    console.print("[green]✓ Graph API token obtained from refresh token![/green]")
                    console.print(f"[dim]Token expires at: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
                    console.print("[dim]You can now use graph_* commands (e.g., graph_mail, graph_teams).[/dim]")
                    return True

            except Exception as e:
                console.print(f"[red]Failed to get Graph token from refresh token: {e}[/red]")
                return False

        console.print(f"[red]Unable to automatically obtain Graph token with {auth_method} authentication.[/red]")
        console.print("[yellow]Try 'get_graph_token' to authenticate with username/password (ROPC flow).[/yellow]")
        return False

    def sync_user_info_from_graph(self) -> bool:
        """
        Sync current user information from Microsoft Graph API /me endpoint.

        Retrieves and saves user details like displayName, userPrincipalName,
        jobTitle, etc. to the current session.

        Returns:
            True if successful, False otherwise
        """
        import requests

        access_token = self.get_access_token(scope="graph")
        if not access_token:
            return False

        try:
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30
            )
            response.raise_for_status()

            user_data = response.json()

            # Save user information to session
            self.current_session_data["user_id"] = user_data.get("id")
            self.current_session_data["user_display_name"] = user_data.get("displayName")
            self.current_session_data["user_principal_name"] = user_data.get("userPrincipalName")
            self.current_session_data["user_job_title"] = user_data.get("jobTitle")
            self.current_session_data["account_name"] = user_data.get("mail") or user_data.get("userPrincipalName")

            # Try to get assigned roles if possible
            try:
                roles_response = requests.get(
                    "https://graph.microsoft.com/v1.0/me/memberOf",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30
                )
                if roles_response.status_code == 200:
                    roles_data = roles_response.json()
                    # Save first few roles for display
                    roles = [r.get("displayName") for r in roles_data.get("value", [])[:5] if r.get("displayName")]
                    if roles:
                        self.current_session_data["user_roles"] = roles
            except Exception:
                pass  # Roles are optional

            self.save_current_session()
            return True

        except requests.exceptions.RequestException:
            return False
        except Exception:
            return False

    # ---------- Azure CLI helpers (login / switch) ----------

    def _az_cli_json(self, args: list[str]) -> Dict[str, Any]:
        proc = subprocess.run(
            ["az", *args, "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,  # PERF-006: Add timeout for session management operations
        )

        if proc.returncode != 0:
            console.print(
                f"[red]az {' '.join(args)} failed with code {proc.returncode}[/red]"
            )
            console.print(f"[red]{proc.stderr}[/red]")
            raise subprocess.CalledProcessError(
                proc.returncode, proc.args, output=proc.stdout, stderr=proc.stderr
            )

        return json.loads(proc.stdout or "{}")

    def azure_login(self) -> None:
        """
        Azure login:
        1) try username/password (az login -u/-p)
        2) if the tenant doesn't allow it (MFA/policy), fallback to interactive az login.
        """
        username = Prompt.ask("[cyan]Azure username (UPN/email)[/cyan]").strip()
        if not username:
            console.print("[red]Username is required for az login.[/red]")
            return

        password = getpass("Azure password: ").strip()
        if not password:
            console.print("[red]Password is required for az login.[/red]")
            return

        # 1) Attempt with username/password
        if self.azure_login_with_credentials(username, password):
            console.print("[green]Azure login (username/password) completed successfully.[/green]")
            return

        # If we're here, azure_login_with_credentials has failed.
        # Check if the message contains known MFA/policy indications.
        console.print(
            "[yellow]Username/password login is not allowed or failed due to MFA/policies "
            "for this tenant.[/yellow]"
        )
        use_fallback = Prompt.ask(
            "[cyan]Fallback to interactive 'az login' (browser/device code)? [y/N][/cyan]",
            default="N"
        ).strip().lower()

        if use_fallback != "y":
            console.print("[red]Azure login failed and no fallback was selected.[/red]")
            return

        # 2) Fallback: interactive az login (without -u/-p)
        cmd = ["az", "login"]
        tenant_id = self.current_session_data.get("tenant_id")
        if tenant_id:
            cmd += ["--tenant", tenant_id]

        console.print(f"[cyan]Running fallback: {' '.join(cmd)}[/cyan]")

        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=90,  # PERF-006: Add timeout for interactive login
        )

        stderr = proc.stderr or ""

        if proc.returncode != 0:
            # Specific case: no accessible subscriptions
            if "No subscriptions found for" in stderr:
                console.print("[yellow]No subscriptions found for this user.[/yellow]")
                console.print(f"[dim]{stderr}[/dim]")
                choice = Prompt.ask(
                    "[cyan]Retry az login with --allow-no-subscriptions (tenant-level only)? [y/N][/cyan]",
                    default="N"
                ).strip().lower()
                if choice == "y":
                    cmd_no_sub = ["az", "login", "--allow-no-subscriptions"]
                    if tenant_id:
                        cmd_no_sub += ["--tenant", tenant_id]
                    console.print(f"[cyan]Running: {' '.join(cmd_no_sub)}[/cyan]")
                    proc2 = subprocess.run(
                        cmd_no_sub,
                        text=True,
                        capture_output=True,
                        timeout=90,  # PERF-006: Add timeout for interactive login
                    )
                    if proc2.returncode != 0:
                        console.print("[red]Interactive az login (no-subscriptions) failed.[/red]")
                        if proc2.stderr:
                            console.print(f"[dim]{proc2.stderr}[/dim]")
                        return
                else:
                    console.print("[red]Azure login failed and no no-subscriptions fallback selected.[/red]")
                    return
            else:
                console.print("[red]Interactive az login failed.[/red]")
                console.print(f"[dim]{stderr}[/dim]")
                return


        try:
            self.azure_sync_from_current_account()
        except Exception as e:
            console.print(
                "[yellow]Login succeeded but sync of current account failed.[/yellow]"
            )
            console.print(f"[dim]{e}[/dim]")
            return

        console.print("[green]Azure login (interactive fallback) completed successfully.[/green]")

    def azure_force_reauth(self) -> bool:
        """
        Forces a new Azure CLI authentication.
        Used when the token is revoked or expired.

        Returns:
            bool: True if re-auth succeeds
        """
        console.print("[yellow]Revoked token detected. Forcing re-authentication...[/yellow]")

        # 1. Logout to clear cached tokens
        try:
            subprocess.run(["az", "logout"], check=False, capture_output=True, timeout=30)  # PERF-006
        except Exception:
            pass  # Ignore logout errors

        # 2. Re-login with the same credentials or mode of the current session
        data = self.current_session_data or {}

        # If we have saved credentials, use them
        username = data.get("account_name")
        if username:
            console.print(f"[cyan]Re-authenticating as {username}...[/cyan]")
            # Try first with credentials (if available)
            # Otherwise fallback to interactive login

        # Interactive login with allow-no-subscriptions
        try:
            proc = subprocess.run(
                ["az", "login", "--allow-no-subscriptions"],
                capture_output=True,
                text=True,
                timeout=90,  # PERF-006: Add timeout for interactive login
            )
            proc.check_returncode()

            # Sync session data
            self.azure_sync_from_current_account()
            console.print("[green]Re-authentication completed successfully![/green]")
            return True

        except subprocess.CalledProcessError as e:
            console.print("[red]Re-authentication failed.[/red]")
            console.print(f"[dim]{e.stderr}[/dim]")
            return False

    def detect_token_error(self, stderr: str) -> bool:
        """
        Detects if the error is due to a revoked/expired token.

        Public method for external modules to check token error conditions.

        Args:
            stderr: stderr output of the az command

        Returns:
            bool: True if it's a token error
        """
        token_error_codes = [
            "TokenIssuedBeforeRevocationTimestamp",
            "AADSTS70043",  # Sign-in frequency check
            "AADSTS700016",  # Invalid token lifetime
            "AADSTS50173",   # FreshTokenNeeded
            "InteractionRequired"
        ]

        return any(code in stderr for code in token_error_codes)

    def require_tenant_id(self) -> bool:
        """
        Check if the current session has a valid tenant_id.

        This is a public method used by Azure enumeration modules to validate
        that Azure authentication has been completed before running operations.

        Returns:
            bool: True if tenant_id exists, False otherwise

        Note:
            When this returns False, the caller should display an error message
            and prompt the user to run 'az_login' first.
        """
        data = self.current_session_data or {}
        tenant_id = data.get("tenant_id")

        if not tenant_id:
            console.print(
                "[yellow]Current session has no tenant_id. "
                "Run 'az_login' in this session first.[/yellow]"
            )
            return False

        return True

    def extract_tenant_from_token(self) -> Optional[str]:
        """
        Extract tenant ID from an access token (JWT).

        Decodes the JWT token to extract the 'tid' claim.

        Returns:
            Tenant ID if found, None otherwise
        """
        try:
            credential = self.get_credential(scope="management")
            if not credential:
                return None

            # Get a token
            token = credential.get_token("https://management.azure.com/.default")
            access_token = token.token

            # Decode JWT (without verification - we just need the claims)
            # JWT format: header.payload.signature
            parts = access_token.split('.')
            if len(parts) != 3:
                return None

            # Decode payload (add padding if needed)
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            # Extract tenant ID from 'tid' claim
            tenant_id = claims.get('tid')
            return tenant_id

        except Exception as e:
            console.print(f"[dim]Could not extract tenant from token: {e}[/dim]")
            return None

    def sync_subscriptions_from_sdk(self) -> bool:
        """
        Retrieve and sync subscription information using Azure SDK.

        Used after SDK-based authentication (interactive, device_code, service_principal)
        to populate subscription_id and subscription_name in the session.

        Returns:
            True if successful, False otherwise
        """
        try:
            from azure.mgmt.subscription import SubscriptionClient

            credential = self.get_credential(scope="management")
            if not credential:
                return False

            # Get subscription client
            subscription_client = SubscriptionClient(credential)

            # List all accessible subscriptions
            subscriptions = list(subscription_client.subscriptions.list())

            if not subscriptions:
                console.print("[yellow]No accessible subscriptions found.[/yellow]")
                return False

            # If only one subscription, use it automatically
            if len(subscriptions) == 1:
                sub = subscriptions[0]
                self.current_session_data["subscription_id"] = sub.subscription_id
                self.current_session_data["subscription_name"] = sub.display_name
                # tenant_id is already set by extract_tenant_from_token()
                self.save_current_session()
                console.print(f"[green]Using subscription: {sub.display_name} ({sub.subscription_id})[/green]")
                return True

            # Multiple subscriptions - use the first one (or could ask user)
            sub = subscriptions[0]
            self.current_session_data["subscription_id"] = sub.subscription_id
            self.current_session_data["subscription_name"] = sub.display_name
            # tenant_id is already set by extract_tenant_from_token()
            self.save_current_session()

            console.print(f"[green]Using subscription: {sub.display_name} ({sub.subscription_id})[/green]")
            console.print(f"[dim]Found {len(subscriptions)} total subscription(s). Using the first one.[/dim]")
            return True

        except Exception as e:
            console.print(f"[yellow]Could not retrieve subscriptions via SDK: {e}[/yellow]")
            return False

    def azure_sync_from_current_account(self) -> None:
        # Account data (subscription / tenant / user name) from CLI
        data = self._az_cli_json(["account", "show"])
        user_basic = data.get("user") or {}

        sess = self.current_session_data
        sess["cloud"] = "azure"
        sess["subscription_id"] = data.get("id")
        sess["subscription_name"] = data.get("name")
        sess["tenant_id"] = data.get("tenantId")
        sess["account_name"] = user_basic.get("name")

        # Detailed user data from Entra ID
        try:
            user = self._az_cli_json(["ad", "signed-in-user", "show"])
        except subprocess.CalledProcessError:
            user = {}

        sess["user_id"] = user.get("id")
        sess["user_display_name"] = user.get("displayName")
        sess["user_principal_name"] = user.get("userPrincipalName")
        sess["user_job_title"] = user.get("jobTitle")

        self.save_current_session()

    def azure_use_session(self, name: str) -> None:
        from rich.console import Console
        console = Console()

        # Check if session exists before loading
        available = {s["name"] for s in self.list_sessions()}
        if name not in available:
            console.print(f"[red]Session '{name}' not found.[/red]")
            return

        self.create_or_load_session(name)

        # Invalidate credential cache when switching sessions
        self.clear_credential_cache()

        if self.current_session_data.get("cloud") != "azure":
            return

        sub_id = self.current_session_data.get("subscription_id")
        if sub_id:
            subprocess.run(
                ["az", "account", "set", "--subscription", sub_id],
                check=True,
                timeout=30,  # PERF-006: Add timeout for account switching
            )

    def azure_login_with_scope(self, scope: str) -> bool:
        """
        Executes az login with a specific scope (e.g. Storage, Graph) and
        updates the current session if it succeeds.
        """
        tenant = self.current_session_data.get("tenant_id")
        cmd = ["az", "login"]
        if tenant:
            cmd += ["--tenant", tenant]
        cmd += ["--scope", scope]

        console.print(
            f"[cyan]Running: {' '.join(cmd)}[/cyan]"
        )

        try:
            subprocess.run(cmd, check=True, timeout=90)  # PERF-006: Add timeout for login
            self.azure_sync_from_current_account()
            return True
        except subprocess.CalledProcessError as e:
            console.print("[red]az login with scope failed.[/red]")
            console.print(f"[dim]{e.stderr}[/dim]")
            return False

    def azure_login_with_credentials(self, username: str, password: str) -> bool:
        """
        Executes az login with username/password for the current session
        and synchronizes data (subscription, tenant, user).
        """
        cmd = ["az", "login", "-u", username, "-p", password]

        console.print(f"[cyan]Running: {' '.join(cmd[:-1])} ********[/cyan]")

        try:
            subprocess.run(cmd, check=True, timeout=90)  # PERF-006: Add timeout for login
        except subprocess.CalledProcessError as e:
            console.print("[red]az login with username/password failed.[/red]")
            if e.stderr:
                console.print(f"[dim]{e.stderr}[/dim]")
            return False

        # If login succeeds, update session data
        try:
            self.azure_sync_from_current_account()
        except Exception as e:
            console.print(
                "[yellow]Login succeeded but sync of current account failed.[/yellow]"
            )
            console.print(f"[dim]{e}[/dim]")
            return False

        return True

    def set_password_auth(self, username: str, password: str, tenant_id: str = None) -> bool:
        """
        Configure password-based authentication (ROPC flow) for the current session.

        This uses UsernamePasswordCredential directly without Azure CLI.
        Useful for ADFS and federated scenarios where device code doesn't work.

        Args:
            username: User email or UPN
            password: User password
            tenant_id: Optional tenant ID (if not already set in session)

        Returns:
            True if successful, False otherwise
        """
        if not username or not password:
            console.print("[red]Username and password are required.[/red]")
            return False

        # Set or use existing tenant ID
        if tenant_id:
            self.current_session_data["tenant_id"] = tenant_id
        elif not self.current_session_data.get("tenant_id"):
            console.print("[yellow]No tenant ID set. Using 'organizations' (multi-tenant).[/yellow]")
            self.current_session_data["tenant_id"] = "organizations"

        # Store credentials in session
        self.current_session_data["auth_method"] = "password"
        self.current_session_data["username"] = username
        self.current_session_data["password"] = password
        self.current_session_data["account_name"] = username

        # Clear credential cache
        self._clear_credential_cache()

        # Try to get a token to verify credentials work
        console.print("[dim]Testing credentials...[/dim]")
        try:
            credential = self.get_credential(scope="graph")
            if credential:
                # Try to get a token
                token = credential.get_token("https://graph.microsoft.com/.default")
                if token:
                    console.print("[green]Credentials verified successfully![/green]")

                    # Try to get user info
                    self.current_session_data["graph_access_token"] = token.token
                    self.current_session_data["graph_token_expires_at"] = token.expires_on

                    if self.sync_user_info_from_graph():
                        console.print("[green]User information retrieved.[/green]")

                    self.save_current_session()
                    return True
        except Exception as e:
            console.print(f"[red]Authentication failed: {e}[/red]")
            console.print("[yellow]This may indicate:[/yellow]")
            console.print("  - Incorrect username or password")
            console.print("  - ROPC flow disabled for this tenant/user")
            console.print("  - MFA required (ROPC doesn't support MFA)")
            console.print("  - Conditional Access policy blocking ROPC")
            return False

        console.print("[red]Failed to verify credentials.[/red]")
        return False
