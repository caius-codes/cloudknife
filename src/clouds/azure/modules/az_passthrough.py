# src/clouds/azure/modules/az_passthrough.py

import shlex
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.prompt import Prompt, Confirm

from ..azure_session import AzureSessionManager
from ..utils import execute_with_reauth  # DUP-001: Centralized reauth pattern
from ....logging import get_command_logger

console = Console()
logger = get_command_logger()

# Dangerous commands that could interfere with the session
BLOCKED_COMMANDS = [
    "logout",
    "account clear",
    "config",
]


def _get_az_cli_active_session() -> Optional[Dict[str, Any]]:
    """
    Reads the active Azure CLI session from ~/.azure/azureProfile.json.

    Returns:
        Dict with subscription_id, tenant_id, account_name if found, None otherwise
    """
    azure_profile_path = Path.home() / ".azure" / "azureProfile.json"

    if not azure_profile_path.exists():
        return None

    try:
        # Use utf-8-sig to handle BOM (Byte Order Mark) if present
        with open(azure_profile_path, 'r', encoding='utf-8-sig') as f:
            profile = json.load(f)

        # Find the default subscription
        subscriptions = profile.get("subscriptions", [])
        for sub in subscriptions:
            if sub.get("isDefault", False):
                return {
                    "subscription_id": sub.get("id"),
                    "tenant_id": sub.get("tenantId"),
                    "account_name": sub.get("user", {}).get("name"),
                }

        # If no default, return the first one
        if subscriptions:
            sub = subscriptions[0]
            return {
                "subscription_id": sub.get("id"),
                "tenant_id": sub.get("tenantId"),
                "account_name": sub.get("user", {}).get("name"),
            }
    except (json.JSONDecodeError, IOError) as e:
        console.print(f"[dim]Warning: Could not read Azure CLI profile: {e}[/dim]")
        return None

    return None


def _check_session_match(session_mgr: AzureSessionManager) -> bool:
    """
    Checks if CloudKnife session matches the active az CLI session.

    Args:
        session_mgr: Azure session manager

    Returns:
        bool: True if sessions match or check cannot be performed, False if mismatch detected
    """
    # Get CloudKnife session info
    ck_subscription = session_mgr.current_session_data.get("subscription_id")
    ck_tenant = session_mgr.current_session_data.get("tenant_id")

    # If CloudKnife session has no subscription/tenant (e.g., set_token without metadata),
    # we cannot verify - allow the command
    if not ck_subscription and not ck_tenant:
        return True

    # Get az CLI session info
    az_session = _get_az_cli_active_session()

    if not az_session:
        # Cannot read az CLI session - warn but allow
        console.print(
            "[yellow]⚠️  Warning: Cannot verify az CLI session (no ~/.azure/azureProfile.json found).[/yellow]\n"
            "[dim]The 'az' command will use system credentials which may differ from CloudKnife session.[/dim]"
        )
        return True

    # Compare subscription and tenant
    az_subscription = az_session.get("subscription_id")
    az_tenant = az_session.get("tenant_id")

    # Check for mismatch
    mismatch = False
    mismatch_details = []

    if ck_subscription and az_subscription and ck_subscription != az_subscription:
        mismatch = True
        mismatch_details.append(f"Subscription: CloudKnife={ck_subscription[:8]}... vs az CLI={az_subscription[:8]}...")

    if ck_tenant and az_tenant and ck_tenant != az_tenant:
        mismatch = True
        mismatch_details.append(f"Tenant: CloudKnife={ck_tenant[:8]}... vs az CLI={az_tenant[:8]}...")

    if mismatch:
        console.print("[bold red]⚠️  Session Mismatch Detected![/bold red]")
        console.print("[yellow]CloudKnife session does NOT match the active az CLI session:[/yellow]")
        for detail in mismatch_details:
            console.print(f"  • {detail}")
        console.print(
            "\n[cyan]To fix this, run:[/cyan] [bold]login_az_cli[/bold]\n"
            "[dim]This will authenticate with az CLI using the CloudKnife session credentials.[/dim]"
        )

        # Ask user if they want to continue anyway
        proceed = Confirm.ask(
            "[yellow]Do you want to continue with the az command anyway?[/yellow]",
            default=False
        )

        return proceed

    # Sessions match or partial info - allow
    return True


def _is_command_blocked(cmd_args: List[str]) -> bool:
    """
    Checks if the command is in the blacklist.

    Args:
        cmd_args: List of az command arguments

    Returns:
        bool: True if the command is blocked
    """
    cmd_str = " ".join(cmd_args).lower()
    return any(blocked in cmd_str for blocked in BLOCKED_COMMANDS)


def _execute_az_command(full_cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Executes an az command with timeout and error handling.

    Args:
        full_cmd: Complete command to execute (including 'az')
        timeout: Timeout in seconds (default: 5 minutes)

    Returns:
        subprocess.CompletedProcess: Command result

    Raises:
        subprocess.CalledProcessError: If the command fails
        subprocess.TimeoutExpired: If the command exceeds the timeout
        FileNotFoundError: If az CLI is not installed
    """
    return subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_az_command(session_mgr: AzureSessionManager, cmd_args: Optional[List[str]] = None) -> None:
    """
    Executes an arbitrary az command, using the current session for login context.
    Example: az storage account list --query "[].name"

    Args:
        session_mgr: Azure session manager
        cmd_args: Command arguments (if None, asks user for input)
    """
    # If cmd_args is provided and not empty, use it directly
    if cmd_args:
        cmd_str = " ".join(cmd_args)
    else:
        # Otherwise ask the user
        cmd_str = Prompt.ask("[cyan]az[/cyan]").strip()

    if not cmd_str:
        console.print("[red]No az command provided.[/red]")
        return

    # Optional: make sure the session is initialized
    if not session_mgr.current_session:
        console.print("[yellow]No Azure session selected. Use or create a session first.[/yellow]")
        return

    # Parse the command (use different name to avoid shadowing)
    parsed_args = shlex.split(cmd_str)
    full_cmd = ["az"] + parsed_args

    # Block dangerous commands
    if _is_command_blocked(parsed_args):
        console.print(
            f"[red]Command blocked for safety: {' '.join(parsed_args)}[/red]\n"
            "[yellow]This command might interfere with the current session.[/yellow]"
        )
        # Log blocked command
        logger.log_command(
            cloud="azure",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=" ".join(full_cmd),
            status="blocked",
        )
        return

    # Check if CloudKnife session matches az CLI session
    if not _check_session_match(session_mgr):
        console.print("[yellow]Command aborted due to session mismatch.[/yellow]")
        # Log aborted command
        logger.log_command(
            cloud="azure",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=" ".join(full_cmd),
            status="aborted",
            error_message="Session mismatch with az CLI",
        )
        return

    console.print(f"[cyan]Running:[/cyan] {' '.join(full_cmd)}")

    # DUP-001: Use centralized execute_with_reauth helper
    proc = execute_with_reauth(
        session_mgr,
        full_cmd,
        timeout=300,  # 5 minutes for passthrough commands
        error_context=f"execute command: {' '.join(full_cmd[:3])}...",
    )

    if not proc:
        # Command failed - error messages already shown by helper
        # Log failure
        logger.log_command(
            cloud="azure",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=" ".join(full_cmd),
            status="failed",
            error_message="Command failed or timed out",
        )
        return

    # Success - show stdout if present
    if proc.stdout:
        console.print(proc.stdout)

    # Log success
    logger.log_command(
        cloud="azure",
        session_id=session_mgr.session_id or "unknown",
        session_name=session_mgr.current_session or "unknown",
        command=" ".join(full_cmd),
        status="executed",
        exit_code=0,
    )
