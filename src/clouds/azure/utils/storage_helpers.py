"""
Azure Storage utility helpers.

Utilities for Azure Storage operations with SAS token and scope-based authentication.
"""

import subprocess
from typing import Tuple, Optional, Callable, TYPE_CHECKING

from rich.console import Console
from rich.prompt import Prompt

if TYPE_CHECKING:
    from ..azure_session import AzureSessionManager

console = Console()


def prompt_storage_auth() -> Tuple[bool, Optional[str]]:
    """
    Prompt user for Azure Storage authentication mode (login vs SAS token).

    This function consolidates the auth mode prompt pattern that was previously
    duplicated across storage-related modules (DUP-007 fix).

    Returns:
        Tuple[bool, Optional[str]]: (use_sas, sas_token)
            - use_sas: True if SAS token should be used, False if AAD login
            - sas_token: The SAS token string if use_sas is True, None otherwise

    Example:
        >>> use_sas, sas_token = prompt_storage_auth()
        >>> if use_sas:
        ...     cmd += ["--sas-token", sas_token]
        ... else:
        ...     cmd += ["--auth-mode", "login"]
    """
    auth_mode = Prompt.ask(
        "[cyan]Auth mode [login/sas] (default: login)[/cyan]",
        default="login"
    ).strip().lower()

    use_sas = auth_mode == "sas"
    sas_token = None

    if use_sas:
        sas_token = Prompt.ask("[cyan]SAS token (starting with '?')[/cyan]").strip()
        if not sas_token:
            console.print("[red]SAS token is required in sas mode.[/red]")
            return use_sas, None

    return use_sas, sas_token


def execute_with_storage_scope_retry(
    session_mgr: "AzureSessionManager",
    operation: Callable[[], any],
    use_sas: bool,
    operation_name: str = "operation",
) -> Optional[any]:
    """
    Execute an Azure Storage operation with automatic retry on AADSTS70043 scope error.

    This function consolidates the AADSTS70043 detection and Storage scope retry
    pattern that was previously duplicated across storage modules (DUP-007 fix).

    Args:
        session_mgr: Azure session manager for scope-based re-authentication
        operation: Callable that executes the storage command (should raise CalledProcessError on failure)
        use_sas: If True, skip scope retry (SAS tokens don't need AAD scopes)
        operation_name: Human-readable name for error messages (e.g., "blob list", "blob download")

    Returns:
        The result of the operation() call if successful, None if failed

    Example:
        >>> def _run_blob_list():
        ...     proc = subprocess.run(["az", "storage", "blob", "list", ...], check=True, ...)
        ...     return json.loads(proc.stdout)
        >>>
        >>> result = execute_with_storage_scope_retry(
        ...     session_mgr,
        ...     _run_blob_list,
        ...     use_sas=False,
        ...     operation_name="blob list"
        ... )
    """
    try:
        return operation()
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""

        # Specific case: expired Storage token / Sign-In Frequency policy
        if (not use_sas
            and "AADSTS70043" in stderr
            and "https://storage.azure.com/.default" in stderr):

            console.print(
                "[yellow]Token for Azure Storage is invalid/expired or "
                "requires additional MFA (sign-in frequency policy).[/yellow]"
            )
            console.print(f"[dim]{stderr}[/dim]")

            retry = Prompt.ask(
                "[cyan]Retry az login with Storage scope "
                "('https://storage.azure.com/.default')? [y/N][/cyan]",
                default="N"
            ).strip().lower()

            if retry == "y":
                # Attempt re-login with Storage scope
                if hasattr(session_mgr, "azure_login_with_scope") and session_mgr.azure_login_with_scope(
                    "https://storage.azure.com/.default"
                ):
                    try:
                        return operation()
                    except subprocess.CalledProcessError as e2:
                        console.print(f"[red]Error running {operation_name} after re-login.[/red]")
                        if e2.stderr:
                            console.print(f"[red]{e2.stderr}[/red]")
                        return None
                else:
                    console.print(
                        "[red]azure_login_with_scope not available or login failed.[/red]"
                    )
                    return None
            else:
                console.print(f"[yellow]Retry cancelled. {operation_name} aborted.[/yellow]")
                return None
        else:
            # Different error - display and return None
            console.print(f"[red]Error running {operation_name}.[/red]")
            console.print(f"[red]{stderr}[/red]")
            return None
