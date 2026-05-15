from abc import ABC, abstractmethod
from pathlib import Path
import json
import os
import re
from typing import Dict, Optional, Any, List

# Regex for valid session names (prevents path traversal)
_VALID_SESSION_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


def get_cloudknife_home() -> Path:
    """
    Return the CloudKnife home directory (~/.cloudknife/).

    This is the centralized location for all CloudKnife data:
    - Sessions: ~/.cloudknife/sessions/{cloud}/
    - Exfiltration: ~/.cloudknife/exfil/{cloud}/{session}/{service}/

    Can be overridden via CLOUDKNIFE_HOME environment variable.
    """
    env_override = os.environ.get("CLOUDKNIFE_HOME")
    if env_override:
        return Path(env_override).expanduser().resolve()
    return Path.home() / ".cloudknife"


class SessionManager(ABC):
    """
    Abstract base class for cloud session management.

    Handles session lifecycle, file I/O, and enumeration data storage.
    Cloud-specific implementations must provide configuration defaults.
    """

    # ---------- Abstract methods (must be implemented by subclasses) ----------

    @abstractmethod
    def _initialize_session_defaults(self) -> None:
        """
        Initialize cloud-specific default configuration values.

        Called during create_or_load_session() to set cloud-specific defaults.
        Each cloud should set appropriate defaults:
        - AWS: region="us-east-1", regions=[]
        - GCP: auth_method=None, project_id=None, default_zone="us-central1-a", zones=[]
        - Azure: cloud="azure", default_location="westeurope", locations=[]
        """
        pass

    @abstractmethod
    def _get_session_list_fields(self, data: Dict[str, Any], session_name: str) -> Dict[str, Any]:
        """
        Return cloud-specific fields for list_sessions() output.

        Args:
            data: The loaded session data
            session_name: Name of the session file

        Returns:
            Dict with cloud-specific fields to include in session list

        Example AWS implementation:
            return {
                "name": session_name,
                "session_id": data.get("session_id", ""),
                "keys_set": bool(data.get("access_key")),
                "region": data.get("region", "us-east-1"),
                "regions": data.get("regions", []),
                "current": session_name == self.current_session,
            }
        """
        pass

    # ---------- Concrete methods (shared across all clouds) ----------
    def __init__(self, sessions_dir: str):
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[str] = None
        self.current_session_data: Dict[str, Any] = {}
        self.enumerated_data: Dict[str, Dict[str, Any]] = {}

    # ---------- Core session lifecycle ----------

    @staticmethod
    def validate_session_name(session_name: str) -> bool:
        """Validate session name to prevent path traversal attacks."""
        return bool(_VALID_SESSION_NAME.match(session_name))

    def create_or_load_session(self, session_name: str) -> None:
        if not self.validate_session_name(session_name):
            raise ValueError(
                f"Invalid session name '{session_name}'. "
                "Only alphanumeric characters, hyphens, and underscores are allowed."
            )
        session_file = self.sessions_dir / f"{session_name}.json"
        if session_file.exists():
            with open(session_file, "r") as f:
                self.current_session_data = json.load(f)
        else:
            self.current_session_data = {}
            # PERF-004: Removed duplicate write - save_current_session() below handles it

        self.current_session = session_name

        # Load enumeration data if present.
        # Always assign (not setdefault) so stale in-memory data from a previous
        # run in the same process is never surfaced when the file no longer exists.
        enum_file = self.sessions_dir / f"{session_name}_enum.json"
        if enum_file.exists():
            with open(enum_file, "r") as f:
                self.enumerated_data[session_name] = json.load(f)
        else:
            self.enumerated_data[session_name] = {}

        # Generate session_id if it doesn't exist (common across all clouds)
        if "session_id" not in self.current_session_data:
            import uuid
            self.current_session_data["session_id"] = str(uuid.uuid4())

        # Let subclass set cloud-specific defaults
        self._initialize_session_defaults()

        self.save_current_session()

    @property
    def session_id(self) -> Optional[str]:
        """Return the current session UUID."""
        return self.current_session_data.get("session_id")

    def _save_session_data(self, session_name: Optional[str] = None) -> None:
        if not session_name:
            session_name = self.current_session
        if not session_name:
            return
        session_file = self.sessions_dir / f"{session_name}.json"
        with open(session_file, "w") as f:
            json.dump(self.current_session_data, f, indent=2)
        os.chmod(session_file, 0o600)

    def save_current_session(self) -> None:
        if not self.current_session:
            return
        self._save_session_data(self.current_session)

        # Save enumeration data if any
        if self.current_session in self.enumerated_data:
            enum_file = self.sessions_dir / f"{self.current_session}_enum.json"
            with open(enum_file, "w") as f:
                json.dump(self.enumerated_data[self.current_session], f, indent=2)
            os.chmod(enum_file, 0o600)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all saved sessions with cloud-specific fields."""
        sessions: List[Dict[str, Any]] = []
        for session_file in self.sessions_dir.glob("*.json"):
            if session_file.stem.endswith("_enum"):
                continue
            try:
                with open(session_file, "r") as f:
                    data = json.load(f)
                # Skip files that aren't session dicts (e.g. exfil downloads accidentally placed here)
                if not isinstance(data, dict):
                    continue
                # Delegate to subclass for cloud-specific fields
                session_info = self._get_session_list_fields(data, session_file.stem)
                sessions.append(session_info)
            except Exception as e:
                # Warn about corrupted session files but continue listing others
                from rich.console import Console
                console = Console()
                console.print(f"[yellow]⚠ Warning: Corrupted session file '{session_file.name}': {e}[/yellow]")
                continue
        return sessions

    def delete_session(self, session_name: str) -> bool:
        """
        Returns True if deleted, False if refused (only one session or current).
        """
        all_sessions = [
            f for f in self.sessions_dir.glob("*.json") if not f.stem.endswith("_enum")
        ]
        if len(all_sessions) <= 1:
            return False
        if session_name == self.current_session:
            return False

        session_file = self.sessions_dir / f"{session_name}.json"
        enum_file = self.sessions_dir / f"{session_name}_enum.json"
        deleted = False

        if session_file.exists():
            session_file.unlink()
            deleted = True
        if enum_file.exists():
            enum_file.unlink()
        if session_name in self.enumerated_data:
            del self.enumerated_data[session_name]

        return deleted

    # ---------- New: delete ALL sessions ----------

    def delete_all_sessions(self) -> int:
        """
        Delete all saved sessions (both *.json and *_enum.json) and clear in-memory state.

        Returns the number of sessions deleted.
        """
        # Delete all .json files (*.json pattern matches both session files and *_enum.json)
        deleted = 0
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                session_file.unlink()
                # Count only primary session files, not the companion *_enum.json
                if not session_file.name.endswith("_enum.json"):
                    deleted += 1
            except Exception:
                continue

        # Clear in-memory state
        self.current_session = None
        self.current_session_data = {}
        self.enumerated_data = {}

        return deleted

    # ---------- Exfil directory ----------

    def get_exfil_dir(self, service: str) -> Path:
        """
        Return (and create) the exfil output directory for the current session.

        Structure: ~/.cloudknife/exfil/{cloud}/{session_name}/{service}/
        Example:   ~/.cloudknife/exfil/azure/Yuki/mail/

        The cloud name is derived from the sessions_dir name (e.g. 'azure', 'aws', 'gcp').
        """
        cloud = self.sessions_dir.name          # e.g. "azure"
        session = self.current_session or "default"
        exfil_path = get_cloudknife_home() / "exfil" / cloud / session / service
        exfil_path.mkdir(parents=True, exist_ok=True)
        return exfil_path

    # ---------- Enumeration data ----------

    def save_enumeration_data(self, data_type: str, data: Any) -> None:
        """Save enumeration results for the current session."""
        if not self.current_session:
            return
        self.enumerated_data.setdefault(self.current_session, {})
        self.enumerated_data[self.current_session][data_type] = data
        self.save_current_session()

    def get_enumeration_data(self, data_type: str) -> Optional[Any]:
        """Retrieve enumeration results from the current session."""
        if not self.current_session:
            return None
        return self.enumerated_data.get(self.current_session, {}).get(data_type)