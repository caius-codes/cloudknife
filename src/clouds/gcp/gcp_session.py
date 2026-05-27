"""
GCP Session Manager for Cloud Knife.

Handles authentication via:
- Service Account JSON key file
- Application Default Credentials (gcloud auth application-default login)
- Metadata server (when running on GCE/GKE)
"""

from pathlib import Path
import json
import os
from typing import Dict, Optional, Any, List

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as OAuth2Credentials
from google.auth import default as google_auth_default
from google.auth.credentials import Credentials
from google.auth.transport.requests import Request
from google.cloud import resourcemanager_v3
import requests

from src.core.session import SessionManager


class GCPSessionManager(SessionManager):
    """
    Manages GCP sessions: credentials, projects, and enumeration results.

    GCP is project-centric, so we track accessible projects instead of regions.
    """

    def __init__(self, sessions_dir: str = "sessions/gcp"):
        super().__init__(sessions_dir)
        self._credentials: Optional[Credentials] = None

    # ---------- Implement abstract methods ----------

    def _initialize_session_defaults(self) -> None:
        """Set GCP-specific defaults."""
        self._credentials = None  # Clear cache on session switch

        self.current_session_data.setdefault("auth_method", None)
        self.current_session_data.setdefault("service_account_file", None)  # Kept for backward compatibility
        self.current_session_data.setdefault("service_account_json", None)  # New: stores SA JSON directly (like AWS)
        self.current_session_data.setdefault("access_token", None)
        self.current_session_data.setdefault("project_id", None)
        self.current_session_data.setdefault("projects", [])
        self.current_session_data.setdefault("default_zone", "us-central1-a")
        self.current_session_data.setdefault("zones", [])

    def _get_session_list_fields(self, data: Dict[str, Any], session_name: str) -> Dict[str, Any]:
        """Return GCP-specific session list fields."""
        return {
            "name": session_name,
            "session_id": data.get("session_id", ""),
            "auth_configured": data.get("auth_method") is not None,
            "auth_method": data.get("auth_method", ""),
            "project_id": data.get("project_id", ""),
            "service_account": data.get("service_account_email", ""),
            "impersonated_sa": data.get("impersonated_sa", ""),
            "current": session_name == self.current_session,
        }

    # ---------- Authentication ----------

    def set_service_account(self, key_file_path: str) -> bool:
        """
        Configure authentication using a service account JSON key file.

        Note: If project_id is missing, attempts to infer it from client_email
        and prompts user for confirmation.

        Returns True on success, False if the file is invalid.
        """
        try:
            path = Path(key_file_path).expanduser().resolve()
            if not path.exists():
                return False

            # Validate the JSON structure
            with open(path, "r") as f:
                key_data = json.load(f)

            # Only private_key and client_email are absolutely required
            # project_id is optional (some SA keys don't include it)
            required_fields = ["type", "private_key", "client_email"]
            if not all(field in key_data for field in required_fields):
                return False

            if key_data.get("type") != "service_account":
                return False

            # Validate that the private key is properly formatted
            try:
                # Test that the key can be loaded (this will catch malformed keys)
                service_account.Credentials.from_service_account_info(
                    key_data,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
            except ValueError as e:
                from rich.console import Console
                console = Console()
                console.print(f"\n[red]✗ Invalid service account key:[/red] {str(e)}")
                console.print("[yellow]The private_key field in the JSON is malformed.[/yellow]")
                console.print("[dim]Hint: Check that the private_key field has proper newlines (\\n) between lines.[/dim]\n")
                return False

            # Store configuration
            self.current_session_data["auth_method"] = "service_account"
            self.current_session_data["service_account_file"] = str(path)  # Kept for backward compatibility
            self.current_session_data["service_account_json"] = key_data  # Store JSON directly (like AWS stores keys)
            self.current_session_data["service_account_email"] = key_data.get("client_email")

            # Handle project_id
            project_id = key_data.get("project_id")

            if not project_id:
                # Try to infer project_id from client_email
                # Format: name@PROJECT-ID.iam.gserviceaccount.com
                client_email = key_data.get("client_email", "")
                inferred_project = self._infer_project_from_email(client_email)

                if inferred_project:
                    # Ask user if they want to use the inferred project
                    from rich.console import Console
                    from rich.prompt import Confirm

                    console = Console()
                    console.print(f"\n[yellow]⚠️  'project_id' not found in service account key file.[/yellow]")
                    console.print(f"[cyan]Inferred project ID from service account email: [bold]{inferred_project}[/bold][/cyan]")

                    if Confirm.ask(f"Set '{inferred_project}' as default project?", default=True):
                        project_id = inferred_project
                        console.print(f"[green]✓ Project set to: {project_id}[/green]")
                    else:
                        console.print("[dim]Project not set. Use 'set_project <project-id>' to configure it later.[/dim]")

            self.current_session_data["project_id"] = project_id

            # Clear cached credentials
            self._credentials = None

            self.save_current_session()
            return True

        except (json.JSONDecodeError, KeyError, OSError):
            return False

    def _infer_project_from_email(self, email: str) -> str | None:
        """
        Infer GCP project ID from service account email.

        Service account emails have format: name@PROJECT-ID.iam.gserviceaccount.com

        Args:
            email: Service account email address

        Returns:
            Inferred project ID or None if pattern doesn't match
        """
        import re

        # Pattern: anything@PROJECT-ID.iam.gserviceaccount.com
        pattern = r'^[^@]+@([^.]+)\.iam\.gserviceaccount\.com$'
        match = re.match(pattern, email)

        if match:
            return match.group(1)

        return None

    def use_application_default_credentials(self) -> bool:
        """
        Configure authentication using Application Default Credentials.

        This uses credentials from:
        - GOOGLE_APPLICATION_CREDENTIALS env var
        - gcloud auth application-default login
        - Metadata server (on GCE/GKE)

        Returns True on success.
        """
        try:
            credentials, project = google_auth_default()

            self.current_session_data["auth_method"] = "adc"
            self.current_session_data["service_account_file"] = None
            self.current_session_data["service_account_json"] = None
            self.current_session_data["project_id"] = project

            # Try to get service account email if available
            if hasattr(credentials, "service_account_email"):
                self.current_session_data["service_account_email"] = credentials.service_account_email
            else:
                self.current_session_data["service_account_email"] = None

            self._credentials = credentials
            self.save_current_session()
            return True

        except Exception:
            return False

    def set_access_token(
        self,
        token: str,
        project_id: str = None,
        service_account_email: str = None,
        skip_tokeninfo: bool = False,
    ) -> bool:
        """
        Configure authentication using a raw access token.

        Access tokens are typically obtained from:
        - Metadata server (http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token)
        - SSRF vulnerabilities
        - Compromised applications
        - Stolen credentials

        Note: Access tokens expire (typically 1 hour) and cannot be refreshed without additional credentials.

        Args:
            token: The access token string
            project_id: Optional project ID (required for most operations)
            service_account_email: Optional service account email (useful when tokeninfo doesn't return it)
            skip_tokeninfo: If True, skip fetching token info (used internally)

        Returns True on success.
        """
        token = token.strip()
        if not token:
            return False

        # Store configuration
        self.current_session_data["auth_method"] = "access_token"
        self.current_session_data["access_token"] = token
        self.current_session_data["service_account_file"] = None
        self.current_session_data["service_account_json"] = None

        if project_id:
            self.current_session_data["project_id"] = project_id

        # If service account email provided directly, use it
        if service_account_email:
            self.current_session_data["service_account_email"] = service_account_email.strip()

        # Clear cached credentials
        self._credentials = None

        # Try to fetch token info to get the identity (email/service account) if not provided
        if not skip_tokeninfo and not service_account_email:
            try:
                response = requests.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"access_token": token},
                    timeout=10,
                )
                if response.status_code == 200:
                    token_info = response.json()
                    email = token_info.get("email")
                    if email:
                        self.current_session_data["service_account_email"] = email
            except Exception:
                # Token info fetch failed, but we can still use the token
                pass

        self.save_current_session()
        return True

    def set_access_token_from_file(self, token_file_path: str, project_id: str = None) -> bool:
        """
        Configure authentication using an access token from a file.

        Args:
            token_file_path: Path to file containing the access token
            project_id: Optional project ID

        Returns True on success.
        """
        try:
            path = Path(token_file_path).expanduser().resolve()
            if not path.exists():
                return False

            with open(path, "r") as f:
                token = f.read().strip()

            return self.set_access_token(token, project_id)

        except (OSError, IOError):
            return False

    def get_token_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the current access token.

        Calls Google's tokeninfo endpoint to retrieve:
        - Token expiration
        - Scopes
        - Associated email/service account
        - Audience

        Returns None if no token is configured or if the token is invalid.
        """
        token = self.current_session_data.get("access_token")
        if not token:
            # Try to get token from credentials if using other auth methods
            creds = self.get_credentials()
            if creds and hasattr(creds, "token"):
                token = creds.token
            else:
                return None

        try:
            response = requests.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token},
                timeout=10,
            )

            if response.status_code == 200:
                return response.json()
            else:
                # Protect against non-JSON responses
                try:
                    error_data = response.json()
                    return {"error": error_data.get("error_description", "Invalid token")}
                except (ValueError, requests.exceptions.JSONDecodeError):
                    return {"error": f"HTTP {response.status_code}: {response.text[:100]}"}

        except Exception as e:
            return {"error": str(e)}

    def get_credentials(self, scopes: Optional[List[str]] = None) -> Optional[Credentials]:
        """
        Get Google Cloud credentials based on the configured auth method.

        Args:
            scopes: Optional list of OAuth scopes to request. If not provided,
                   uses the default cloud-platform scope.

        Returns None if no auth method is configured.
        """
        # Use default scopes if not provided
        if scopes is None:
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]

        # Return cached credentials only if using default scopes
        # (custom scopes require fresh credentials)
        if self._credentials is not None and scopes == ["https://www.googleapis.com/auth/cloud-platform"]:
            return self._credentials

        auth_method = self.current_session_data.get("auth_method")

        if auth_method == "service_account":
            # Try JSON from session_data first (new method, like AWS)
            sa_json = self.current_session_data.get("service_account_json")
            if sa_json:
                try:
                    credentials = service_account.Credentials.from_service_account_info(
                        sa_json,
                        scopes=scopes,
                    )
                    # Cache only if using default scopes
                    if scopes == ["https://www.googleapis.com/auth/cloud-platform"]:
                        self._credentials = credentials
                    return credentials
                except ValueError as e:
                    from rich.console import Console
                    console = Console()
                    console.print(f"\n[red]✗ Invalid service account credentials:[/red] {str(e)}")
                    console.print("[yellow]The service account JSON key is malformed.[/yellow]")
                    console.print("[dim]Hint: Check that the private_key field has proper newlines (\\n).[/dim]\n")
                    return None

            # Fallback to file path (backward compatibility with existing sessions)
            key_file = self.current_session_data.get("service_account_file")
            if key_file and Path(key_file).exists():
                try:
                    credentials = service_account.Credentials.from_service_account_file(
                        key_file,
                        scopes=scopes,
                    )
                    # Cache only if using default scopes
                    if scopes == ["https://www.googleapis.com/auth/cloud-platform"]:
                        self._credentials = credentials
                    return credentials
                except ValueError as e:
                    from rich.console import Console
                    console = Console()
                    console.print(f"\n[red]✗ Invalid service account key file:[/red] {str(e)}")
                    console.print(f"[yellow]The key file at {key_file} is malformed.[/yellow]")
                    console.print("[dim]Hint: Check that the private_key field has proper newlines (\\n).[/dim]\n")
                    return None

        elif auth_method == "adc":
            try:
                credentials, _ = google_auth_default(scopes=scopes)
                # Cache only if using default scopes
                if scopes == ["https://www.googleapis.com/auth/cloud-platform"]:
                    self._credentials = credentials
                return credentials
            except Exception:
                pass

        elif auth_method == "access_token":
            token = self.current_session_data.get("access_token")
            if token:
                # Create credentials from raw access token
                # Note: These credentials cannot be refreshed
                # Access tokens already have fixed scopes, so we ignore the scopes parameter
                credentials = OAuth2Credentials(token=token)
                if scopes == ["https://www.googleapis.com/auth/cloud-platform"]:
                    self._credentials = credentials
                return credentials

        return None

    def has_credentials(self) -> bool:
        """Check if valid credentials are configured."""
        return self.get_credentials() is not None

    def get_access_token(self) -> Optional[str]:
        """
        Get a valid access token from the current session.

        For access_token auth: returns the stored token directly.
        For service_account/adc auth: refreshes credentials and returns the token.

        Returns None if no auth method is configured or refresh fails.

        This method consolidates token retrieval logic that was previously
        duplicated across multiple modules (DUP-004 fix).
        """
        auth_method = self.current_session_data.get("auth_method")

        if auth_method == "access_token":
            # Return stored access token directly
            return self.current_session_data.get("access_token")
        else:
            # For service_account or adc: get credentials and refresh
            credentials = self.get_credentials()
            if credentials:
                try:
                    # Refresh credentials to get a valid token
                    credentials.refresh(Request())
                    return credentials.token
                except Exception:
                    # Refresh failed (network issue, expired credentials, etc.)
                    pass
        return None

    # ---------- Project handling ----------

    @property
    def default_project(self) -> Optional[str]:
        """Get the default project ID."""
        return self.current_session_data.get("project_id")

    @property
    def configured_projects(self) -> List[str]:
        """
        Get the list of projects to enumerate.

        If empty, modules should discover accessible projects automatically.
        """
        return self.current_session_data.get("projects", [])

    def set_project(self, project_id: str) -> None:
        """Set the default project."""
        self.current_session_data["project_id"] = project_id
        self.save_current_session()

    def set_projects(self, projects: List[str]) -> None:
        """Set the list of projects to enumerate."""
        self.current_session_data["projects"] = projects
        self.save_current_session()

    def discover_accessible_projects(self) -> List[str]:
        """
        Discover all projects accessible to the current credentials.

        Uses the Resource Manager API to search for projects.
        """
        credentials = self.get_credentials()
        if not credentials:
            return []

        try:
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            projects = []

            # Search for all accessible projects
            for project in client.search_projects():
                if project.state.name == "ACTIVE":
                    projects.append(project.project_id)

            return projects

        except Exception:
            # If search fails, try to use the default project
            default = self.default_project
            return [default] if default else []

    # ---------- Zone handling ----------

    @property
    def default_zone(self) -> str:
        """Get the default zone."""
        return self.current_session_data.get("default_zone", "us-central1-a")

    @property
    def configured_zones(self) -> List[str]:
        """Get the configured zones list. Empty means enumerate all zones."""
        return self.current_session_data.get("zones", [])

    def set_zones(self, zones: List[str]) -> None:
        """Set the zones to enumerate. Pass ["all"] or [] to enumerate all zones."""
        if zones == ["all"]:
            zones = []
        self.current_session_data["zones"] = zones
        self.save_current_session()

    # ---------- Session management ----------

    def delete_all_sessions(self) -> int:
        """Override to clear GCP-specific credential cache."""
        count = super().delete_all_sessions()
        self._credentials = None
        return count
