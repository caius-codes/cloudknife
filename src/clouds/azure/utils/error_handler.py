# src/clouds/azure/utils/error_handler.py
"""
Centralized error handling for Azure SDK operations.

Provides user-friendly error messages and handles common Azure SDK exceptions
like authentication failures, permission errors, and API rate limiting.
"""

from typing import Optional
from rich.console import Console

from azure.core.exceptions import (
    HttpResponseError,
    ClientAuthenticationError,
    ResourceNotFoundError,
    ServiceRequestError,
    ResourceExistsError,
)

console = Console()


def handle_azure_error(error: Exception, operation: str, context: Optional[str] = None) -> None:
    """
    Handle Azure SDK errors with user-friendly messages.

    Args:
        error: The exception raised by Azure SDK
        operation: Description of what operation was being performed
        context: Additional context information (resource name, etc.)
    """
    # Build context prefix if provided
    ctx_prefix = f" ({context})" if context else ""

    # Authentication errors
    if isinstance(error, ClientAuthenticationError):
        error_msg = str(error).lower()
        console.print(f"[red]Authentication failed for {operation}{ctx_prefix}[/red]")

        # Check if it's a Conditional Access policy error
        if any(keyword in error_msg for keyword in ["conditional access", "aadsts", "policy", "criteri", "non rispetta i criteri"]):
            console.print("[yellow]This appears to be a Conditional Access policy restriction.[/yellow]")
            console.print("[cyan]Recommended: Use 'login_az_cli' which bypasses these restrictions.[/cyan]")
        else:
            console.print("[yellow]The current credentials are invalid or expired.[/yellow]")

        console.print("[dim]Try re-authenticating with one of the login commands:[/dim]")
        console.print("[dim]  - login_az_cli (recommended for Conditional Access)[/dim]")
        console.print("[dim]  - set_service_principal[/dim]")
        console.print("[dim]  - login_interactive[/dim]")
        console.print("[dim]  - login_device_code[/dim]")
        console.print(f"[dim]Error details: {error}[/dim]")
        return

    # HTTP Response errors (403, 404, etc.)
    if isinstance(error, HttpResponseError):
        status_code = error.status_code if hasattr(error, "status_code") else None
        error_code = error.error.code if hasattr(error, "error") and error.error else None

        if status_code == 403:
            console.print(f"[red]Permission denied for {operation}{ctx_prefix}[/red]")
            console.print("[yellow]The current account does not have sufficient permissions.[/yellow]")
            console.print("[dim]Required permissions may be missing for this operation.[/dim]")

        elif status_code == 404:
            console.print(f"[red]Resource not found for {operation}{ctx_prefix}[/red]")
            console.print("[yellow]The specified resource does not exist or cannot be accessed.[/yellow]")

        elif status_code == 429:
            console.print(f"[red]Rate limit exceeded for {operation}{ctx_prefix}[/red]")
            console.print("[yellow]Too many requests. Please wait and try again.[/yellow]")

        elif status_code == 401:
            console.print(f"[red]Unauthorized for {operation}{ctx_prefix}[/red]")
            error_msg = str(error).lower()
            if any(keyword in error_msg for keyword in ["conditional access", "policy", "criteri"]):
                console.print("[yellow]This may be caused by Conditional Access policies.[/yellow]")
                console.print("[cyan]Try 'login_az_cli' for better compatibility.[/cyan]")
            else:
                console.print("[yellow]Authentication is required or the token has expired.[/yellow]")
                console.print("[dim]Try re-authenticating with 'login_az_cli'.[/dim]")

        else:
            console.print(f"[red]HTTP {status_code} error for {operation}{ctx_prefix}[/red]")
            if error_code:
                console.print(f"[yellow]Error code: {error_code}[/yellow]")
            console.print(f"[dim]{error}[/dim]")

        return

    # Resource not found
    if isinstance(error, ResourceNotFoundError):
        console.print(f"[red]Resource not found for {operation}{ctx_prefix}[/red]")
        console.print("[yellow]The specified resource does not exist.[/yellow]")
        console.print(f"[dim]{error}[/dim]")
        return

    # Resource already exists
    if isinstance(error, ResourceExistsError):
        console.print(f"[red]Resource already exists for {operation}{ctx_prefix}[/red]")
        console.print("[yellow]The resource you're trying to create already exists.[/yellow]")
        console.print(f"[dim]{error}[/dim]")
        return

    # Service request errors (timeout, connection issues)
    if isinstance(error, ServiceRequestError):
        console.print(f"[red]Service request failed for {operation}{ctx_prefix}[/red]")
        console.print("[yellow]Network or service connectivity issue.[/yellow]")
        console.print("[dim]Check your network connection and try again.[/dim]")
        console.print(f"[dim]{error}[/dim]")
        return

    # Generic error fallback
    console.print(f"[red]Error during {operation}{ctx_prefix}[/red]")
    console.print(f"[yellow]{type(error).__name__}: {error}[/yellow]")


def is_conditional_access_error(error: Exception) -> bool:
    """
    Check if the error is caused by Conditional Access policies.

    Args:
        error: The exception to check

    Returns:
        True if this is a Conditional Access policy error
    """
    error_msg = str(error).lower()
    policy_indicators = [
        "conditional access",
        "aadsts",
        "policy",
        "criteri",  # Italian for "policies"
        "non rispetta i criteri",  # Italian error message
        "does not meet policy requirements",
    ]
    return any(indicator in error_msg for indicator in policy_indicators)


def is_token_expired_error(error: Exception) -> bool:
    """
    Check if the error indicates an expired or revoked token.

    Args:
        error: The exception to check

    Returns:
        True if this is a token expiration error
    """
    if isinstance(error, ClientAuthenticationError):
        error_str = str(error)
        token_error_indicators = [
            "AADSTS70043",  # Sign-in frequency check failed
            "AADSTS700016",  # Invalid token lifetime
            "AADSTS50173",   # FreshTokenNeeded
            "AADSTS700082",  # Token has been revoked
            "TokenIssuedBeforeRevocationTimestamp",
            "InteractionRequired",
        ]
        return any(indicator in error_str for indicator in token_error_indicators)

    return False


def get_error_message(error: Exception) -> str:
    """
    Extract a concise error message from an Azure SDK exception.

    Args:
        error: The exception

    Returns:
        A user-friendly error message string
    """
    if isinstance(error, HttpResponseError):
        error_code = error.error.code if hasattr(error, "error") and error.error else None
        status = error.status_code if hasattr(error, "status_code") else "Unknown"
        if error_code:
            return f"HTTP {status}: {error_code}"
        return f"HTTP {status}: {error.message if hasattr(error, 'message') else str(error)}"

    if isinstance(error, ClientAuthenticationError):
        return f"Authentication failed: {str(error)}"

    return str(error)
