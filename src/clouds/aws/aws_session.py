from typing import Dict, Any, List
from boto3 import Session as Boto3Session

from src.core.session import SessionManager


class AWSSessionManager(SessionManager):
    """AWS-specific session manager with boto3 integration."""

    def __init__(self, sessions_dir: str = "sessions"):
        super().__init__(sessions_dir)

    # ---------- Implement abstract methods ----------

    def _initialize_session_defaults(self) -> None:
        """Set AWS-specific defaults: region and regions list."""
        self.current_session_data.setdefault("region", "us-east-1")
        self.current_session_data.setdefault("regions", [])

    def _get_session_list_fields(self, data: Dict[str, Any], session_name: str) -> Dict[str, Any]:
        """Return AWS-specific session list fields."""
        return {
            "name": session_name,
            "session_id": data.get("session_id", ""),
            "keys_set": bool(data.get("access_key")),
            "region": data.get("region", "us-east-1"),
            "regions": data.get("regions", []),
            "current": session_name == self.current_session,
            "arn": data.get("arn", ""),
            "account": data.get("account", ""),
        }

    # ---------- Boto3 session ----------

    def get_boto3_session(self) -> Boto3Session:
        """
        Get boto3 session with appropriate credentials.

        Supports:
        - Static keys (access_key, secret_key, session_token)
        - SSO profile (uses cached SSO credentials)
        - SSO interactive (uses cached SSO credentials)
        """
        auth_method = self.current_session_data.get("auth_method", "static_keys")

        if auth_method == "sso_profile":
            # For SSO profile, boto3 handles token refresh automatically
            # We use the stored credentials (already obtained from SSO)
            return Boto3Session(
                aws_access_key_id=self.current_session_data.get("access_key"),
                aws_secret_access_key=self.current_session_data.get("secret_key"),
                aws_session_token=self.current_session_data.get("session_token"),
                region_name=self.current_session_data.get("region", "us-east-1"),
            )
        elif auth_method == "sso_interactive":
            # Same as SSO profile - credentials are already cached
            return Boto3Session(
                aws_access_key_id=self.current_session_data.get("access_key"),
                aws_secret_access_key=self.current_session_data.get("secret_key"),
                aws_session_token=self.current_session_data.get("session_token"),
                region_name=self.current_session_data.get("region", "us-east-1"),
            )
        else:
            # Static keys (default behavior)
            return Boto3Session(
                aws_access_key_id=self.current_session_data.get("access_key"),
                aws_secret_access_key=self.current_session_data.get("secret_key"),
                aws_session_token=self.current_session_data.get("session_token"),
                region_name=self.current_session_data.get("region", "us-east-1"),
            )

    # ---------- Regions handling ----------

    @property
    def default_region(self) -> str:
        return self.current_session_data.get("region", "us-east-1")

    @property
    def configured_regions(self) -> List[str]:
        """
        Returns the configured regions list for enumeration.
        If empty, modules should normally use only default_region.
        """
        return self.current_session_data.get("regions", [])

    def set_regions(self, regions: List[str]) -> None:
        """
        Set the regions array (e.g. ["eu-west-1","us-east-1"]) or ["all"].
        """
        self.current_session_data["regions"] = regions
        self.save_current_session()
