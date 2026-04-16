# src/logging/command_logger.py

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal

CloudType = Literal["aws", "azure", "gcp"]


class CommandLogger:
    """
    Centralized logging system for Cloud Knife commands.
    Writes logs in JSONL (JSON Lines) format for each cloud provider.
    """

    def __init__(self, logs_dir: str = "logs"):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True, parents=True)

    def _get_log_file(self, cloud: CloudType) -> Path:
        """
        Get the log file path for the specified cloud provider.

        Args:
            cloud: Cloud provider (aws, azure, gcp)

        Returns:
            Path: Path to the log file
        """
        return self.logs_dir / f"{cloud}_commands.log"

    def log_command(
        self,
        cloud: CloudType,
        session_id: str,
        session_name: str,
        command: str,
        status: str = "executed",
        exit_code: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Log an executed command.

        Args:
            cloud: Cloud provider (aws, azure, gcp)
            session_id: Session UUID
            session_name: Session name
            command: Executed command (e.g. "az ad user list", "enum_users")
            status: Execution status (executed, failed, blocked, timeout)
            exit_code: Command exit code (optional)
            error_message: Error message if present (optional)
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "session_name": session_name,
            "command": command,
            "status": status,
        }

        # Add optional fields if present
        if exit_code is not None:
            log_entry["exit_code"] = exit_code

        if error_message:
            log_entry["error_message"] = error_message

        # Write in append mode (JSONL - one JSON line per entry)
        log_file = self._get_log_file(cloud)
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            # If logging fails, warn the user but don't block the application
            from rich.console import Console
            console = Console()
            console.print(f"[yellow]⚠ Warning: Failed to write command log: {e}[/yellow]")
            console.print(f"[dim]Log file: {log_file}[/dim]")

    def should_log_command(self, command: str) -> bool:
        """
        Check if a command should be logged.

        Excluded: navigation/session management commands.
        Included: operational cloud commands (enum, az, aws, gcp, exfiltration, exploitation).

        Args:
            command: Command name

        Returns:
            bool: True if the command should be logged
        """
        # Commands NOT to log (system/UI commands)
        excluded_commands = {
            "help",
            "?",
            "list_sessions",
            "use_session",
            "delete_session",
            "new_session",
            "clear_sessions",
            "whoami",
            "cloud",
            "exit",
            "quit",
        }

        return command.lower() not in excluded_commands


# Global singleton instance
_command_logger: Optional[CommandLogger] = None


def get_command_logger() -> CommandLogger:
    """
    Get the singleton CommandLogger instance.

    Returns:
        CommandLogger: Logger instance
    """
    global _command_logger
    if _command_logger is None:
        _command_logger = CommandLogger()
    return _command_logger
