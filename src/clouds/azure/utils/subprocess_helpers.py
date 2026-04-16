"""
Azure subprocess execution helpers.

Utilities for executing Azure CLI commands with automatic re-authentication handling.
"""

import subprocess
from typing import List, Optional, TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from ..azure_session import AzureSessionManager

console = Console()


def execute_with_reauth(
    session_mgr: "AzureSessionManager",
    command: List[str],
    timeout: int = 60,
    error_context: str = "command",
) -> Optional[subprocess.CompletedProcess]:
    """
    Execute an Azure CLI command with automatic re-authentication on token expiry.

    This function consolidates the try/detect_token_error/reauth/retry pattern
    that was previously duplicated across multiple Azure modules (DUP-001 fix).

    Args:
        session_mgr: Azure session manager with credentials
        command: Command to execute as a list (e.g., ["az", "ad", "user", "list"])
        timeout: Subprocess timeout in seconds (default: 60)
        error_context: Description of the operation for error messages (e.g., "fetch users")

    Returns:
        subprocess.CompletedProcess if successful, None if failed

    Example:
        >>> proc = execute_with_reauth(
        ...     session_mgr,
        ...     ["az", "rest", "--method", "GET", "--uri", "https://graph.microsoft.com/v1.0/users"],
        ...     error_context="fetch users"
        ... )
        >>> if proc:
        ...     data = json.loads(proc.stdout or "{}")
        ...     users = data.get("value", [])
    """
    # First attempt
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        proc.check_returncode()
        return proc

    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""

        # Check if this is a revoked/expired token error
        if session_mgr.detect_token_error(stderr):
            console.print(
                f"[yellow]⚠ Revoked token detected during {error_context}. "
                f"Attempting re-authentication...[/yellow]"
            )

            # Try re-authentication
            if session_mgr.azure_force_reauth():
                console.print("[dim]Re-authentication successful, retrying command...[/dim]")

                # Retry command after successful re-auth
                try:
                    proc = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    proc.check_returncode()
                    console.print(f"[green]✓ Command succeeded after re-authentication![/green]")
                    return proc

                except subprocess.CalledProcessError as retry_error:
                    console.print(
                        f"[red]✗ Failed to {error_context} even after re-authentication.[/red]"
                    )
                    console.print(f"[dim]Error: {retry_error.stderr}[/dim]")
                    return None
            else:
                console.print(f"[red]✗ Re-authentication failed.[/red]")
                return None
        else:
            # Not a token error - this is a different kind of failure
            console.print(f"[red]✗ Failed to {error_context}.[/red]")
            console.print(f"[dim]Error: {stderr}[/dim]")
            return None

    except subprocess.TimeoutExpired:
        console.print(
            f"[red]✗ Command timed out after {timeout}s while trying to {error_context}.[/red]"
        )
        return None
    except Exception as e:
        console.print(f"[red]✗ Unexpected error during {error_context}: {e}[/red]")
        return None
