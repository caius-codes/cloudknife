"""
AWS Error Handling and Retry Logic.

Provides enhanced error handling with categorization, retry logic,
and structured error reporting for AWS API calls.
"""

import time
import functools
from typing import Callable, Optional, Dict, Any, TypeVar, ParamSpec
from enum import Enum

from botocore.exceptions import ClientError, BotoCoreError
from requests.exceptions import RequestException, ConnectionError as RequestsConnectionError
from rich.console import Console


console = Console()

# Type variables for generic decorator
P = ParamSpec('P')
T = TypeVar('T')


class ErrorCategory(Enum):
    """AWS error categories for better error handling."""

    AUTHENTICATION = "authentication"  # Invalid/expired credentials
    AUTHORIZATION = "authorization"    # Permission denied
    THROTTLING = "throttling"          # Rate limiting
    RESOURCE_NOT_FOUND = "not_found"   # Resource doesn't exist
    VALIDATION = "validation"          # Invalid parameters
    SERVICE_ERROR = "service_error"    # AWS service-side issue
    NETWORK = "network"                # Network/connectivity issues
    UNKNOWN = "unknown"                # Unclassified errors


class AWSError:
    """Structured AWS error information."""

    def __init__(
        self,
        category: ErrorCategory,
        code: str,
        message: str,
        is_retryable: bool = False,
        original_exception: Optional[Exception] = None
    ):
        self.category = category
        self.code = code
        self.message = message
        self.is_retryable = is_retryable
        self.original_exception = original_exception

    def __str__(self) -> str:
        return f"[{self.category.value}] {self.code}: {self.message}"

    def format_for_display(self) -> str:
        """Format error for Rich console display."""
        color_map = {
            ErrorCategory.AUTHENTICATION: "red",
            ErrorCategory.AUTHORIZATION: "yellow",
            ErrorCategory.THROTTLING: "magenta",
            ErrorCategory.RESOURCE_NOT_FOUND: "blue",
            ErrorCategory.VALIDATION: "cyan",
            ErrorCategory.SERVICE_ERROR: "red",
            ErrorCategory.NETWORK: "yellow",
            ErrorCategory.UNKNOWN: "dim",
        }
        color = color_map.get(self.category, "white")
        retry_hint = " (retryable)" if self.is_retryable else ""
        return f"[{color}]{self.code}[/{color}]: {self.message}{retry_hint}"


def categorize_error(exception: Exception) -> AWSError:
    """
    Categorize an exception into structured error information.

    Args:
        exception: The exception to categorize

    Returns:
        AWSError with categorized information
    """
    # AWS ClientError - most common
    if isinstance(exception, ClientError):
        error_info = exception.response.get("Error", {})
        code = error_info.get("Code", "Unknown")
        message = error_info.get("Message", str(exception))

        # Authentication errors
        if code in (
            "InvalidClientTokenId",
            "InvalidClientToken",
            "ExpiredToken",
            "ExpiredTokenException",
            "TokenRefreshRequired",
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
        ):
            return AWSError(
                ErrorCategory.AUTHENTICATION,
                code,
                f"Authentication failed: {message}",
                is_retryable=False,
                original_exception=exception
            )

        # Authorization/permission errors
        if code in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "Forbidden",
            "InsufficientPermissions",
            "NotAuthorized",
            "UnauthorizedAccess",
            "AuthorizationError",
            "AuthFailure",
        ):
            return AWSError(
                ErrorCategory.AUTHORIZATION,
                code,
                f"Permission denied: {message}",
                is_retryable=False,
                original_exception=exception
            )

        # Throttling errors (retryable)
        if code in (
            "Throttling",
            "ThrottlingException",
            "RequestLimitExceeded",
            "TooManyRequestsException",
            "ProvisionedThroughputExceededException",
            "LimitExceededException",
            "RequestThrottled",
            "SlowDown",
        ):
            return AWSError(
                ErrorCategory.THROTTLING,
                code,
                f"Rate limit exceeded: {message}",
                is_retryable=True,
                original_exception=exception
            )

        # Resource not found
        if code in (
            "ResourceNotFoundException",
            "NoSuchEntity",
            "NoSuchBucket",
            "NoSuchKey",
            "DBInstanceNotFound",
            "DBClusterNotFound",
            "InvalidInstanceID.NotFound",
            "InvalidParameterValue",
        ):
            return AWSError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                code,
                f"Resource not found: {message}",
                is_retryable=False,
                original_exception=exception
            )

        # Validation errors
        if code in (
            "ValidationError",
            "ValidationException",
            "InvalidParameterException",
            "InvalidParameterCombination",
            "InvalidParameterValue",
            "MissingParameter",
            "InvalidInput",
        ):
            return AWSError(
                ErrorCategory.VALIDATION,
                code,
                f"Invalid parameter: {message}",
                is_retryable=False,
                original_exception=exception
            )

        # Service errors (may be retryable)
        if code in (
            "InternalError",
            "InternalFailure",
            "ServiceUnavailable",
            "ServiceUnavailableException",
        ):
            return AWSError(
                ErrorCategory.SERVICE_ERROR,
                code,
                f"AWS service error: {message}",
                is_retryable=True,
                original_exception=exception
            )

        # Default ClientError
        return AWSError(
            ErrorCategory.UNKNOWN,
            code,
            message,
            is_retryable=False,
            original_exception=exception
        )

    # BotoCore errors (SDK-level issues)
    if isinstance(exception, BotoCoreError):
        return AWSError(
            ErrorCategory.UNKNOWN,
            "BotoCoreError",
            str(exception),
            is_retryable=True,
            original_exception=exception
        )

    # Network errors (retryable)
    if isinstance(exception, (RequestException, RequestsConnectionError, ConnectionError)):
        return AWSError(
            ErrorCategory.NETWORK,
            "NetworkError",
            f"Network error: {str(exception)[:100]}",
            is_retryable=True,
            original_exception=exception
        )

    # Unknown exception type
    return AWSError(
        ErrorCategory.UNKNOWN,
        type(exception).__name__,
        str(exception)[:200],
        is_retryable=False,
        original_exception=exception
    )


class RetryConfig:
    """Configuration for retry behavior."""

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        """
        Initialize retry configuration.

        Args:
            max_attempts: Maximum number of retry attempts (including first try)
            base_delay: Initial delay between retries in seconds
            max_delay: Maximum delay between retries in seconds
            exponential_base: Base for exponential backoff (2.0 = double each time)
            jitter: Add random jitter to prevent thundering herd
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for the given attempt number.

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            Delay in seconds
        """
        delay = min(
            self.base_delay * (self.exponential_base ** attempt),
            self.max_delay
        )

        if self.jitter:
            import random
            # Add up to 25% jitter
            jitter_amount = delay * 0.25 * random.random()
            delay += jitter_amount

        return delay


def with_retry(
    config: Optional[RetryConfig] = None,
    silent: bool = False
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to add retry logic to AWS API calls.

    Args:
        config: RetryConfig instance (uses default if None)
        silent: If True, don't print retry messages to console

    Returns:
        Decorated function with retry logic

    Example:
        @with_retry(RetryConfig(max_attempts=5))
        def list_buckets(s3_client):
            return s3_client.list_buckets()
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            last_error: Optional[AWSError] = None

            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)

                except Exception as e:
                    last_error = categorize_error(e)

                    # Don't retry if not retryable
                    if not last_error.is_retryable:
                        raise

                    # Don't retry on last attempt
                    if attempt >= config.max_attempts - 1:
                        raise

                    # Calculate delay and wait
                    delay = config.get_delay(attempt)

                    if not silent:
                        console.print(
                            f"[yellow]Retry {attempt + 1}/{config.max_attempts - 1}:[/yellow] "
                            f"{last_error.format_for_display()} "
                            f"[dim](waiting {delay:.1f}s)[/dim]"
                        )

                    time.sleep(delay)

            # Should never reach here, but for type safety
            if last_error and last_error.original_exception:
                raise last_error.original_exception
            raise RuntimeError("Retry logic failed unexpectedly")

        return wrapper
    return decorator


def safe_aws_call(
    func: Callable[P, T],
    *args: P.args,
    default: Optional[T] = None,
    log_error: bool = True,
    **kwargs: P.kwargs
) -> tuple[Optional[T], Optional[AWSError]]:
    """
    Execute an AWS API call safely, returning result and error.

    Args:
        func: Function to call
        *args: Positional arguments for func
        default: Default value to return on error
        log_error: Whether to log errors to console
        **kwargs: Keyword arguments for func

    Returns:
        Tuple of (result, error). If successful, error is None.
        If failed, result is default and error contains AWSError.

    Example:
        result, error = safe_aws_call(s3.list_buckets)
        if error:
            if error.category == ErrorCategory.AUTHORIZATION:
                console.print("Missing S3 permissions")
        else:
            process_buckets(result)
    """
    try:
        result = func(*args, **kwargs)
        return result, None
    except Exception as e:
        error = categorize_error(e)

        if log_error:
            console.print(f"[red]Error:[/red] {error.format_for_display()}")

        return default, error


class ErrorStats:
    """Track error statistics for monitoring."""

    def __init__(self):
        self.errors: Dict[str, int] = {}
        self.by_category: Dict[ErrorCategory, int] = {}
        self.retries: int = 0
        self.successful_retries: int = 0

    def record_error(self, error: AWSError):
        """Record an error occurrence."""
        self.errors[error.code] = self.errors.get(error.code, 0) + 1
        self.by_category[error.category] = self.by_category.get(error.category, 0) + 1

    def record_retry(self, successful: bool = False):
        """Record a retry attempt."""
        self.retries += 1
        if successful:
            self.successful_retries += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get error statistics summary."""
        return {
            "total_errors": sum(self.errors.values()),
            "unique_error_codes": len(self.errors),
            "errors_by_code": dict(self.errors),
            "errors_by_category": {
                cat.value: count for cat, count in self.by_category.items()
            },
            "total_retries": self.retries,
            "successful_retries": self.successful_retries,
            "retry_success_rate": (
                self.successful_retries / self.retries if self.retries > 0 else 0.0
            ),
        }

    def print_summary(self):
        """Print error statistics to console."""
        from rich.table import Table

        summary = self.get_summary()

        table = Table(title="Error Statistics Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Total Errors", str(summary["total_errors"]))
        table.add_row("Unique Error Codes", str(summary["unique_error_codes"]))
        table.add_row("Total Retries", str(summary["total_retries"]))
        table.add_row(
            "Successful Retries",
            f"{summary['successful_retries']} ({summary['retry_success_rate']:.1%})"
        )

        console.print(table)

        if summary["errors_by_category"]:
            console.print("\n[bold]Errors by Category:[/bold]")
            for category, count in summary["errors_by_category"].items():
                console.print(f"  • {category}: {count}")
