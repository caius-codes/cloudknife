"""
GCP API utility functions.

Shared utilities for working with Google Cloud APIs.
"""

from typing import Any
import requests


def parse_error(response: requests.Response) -> str:
    """
    Parse error message from a GCP API response.

    Attempts to extract a human-readable error message from the response.
    Falls back to the raw response text if parsing fails.

    This function consolidates error parsing logic that was previously
    duplicated across multiple modules (DUP-005 fix).

    Args:
        response: The requests.Response object from a failed API call

    Returns:
        A string containing the error message

    Example:
        >>> response = requests.post(url, ...)
        >>> if response.status_code != 200:
        >>>     error_msg = parse_error(response)
        >>>     console.print(f"[red]API Error: {error_msg}[/red]")
    """
    try:
        error_json = response.json()
        if isinstance(error_json, dict):
            # Try to extract nested error message from GCP API error format
            # Typical format: {"error": {"message": "...", "code": 403, ...}}
            error_obj = error_json.get("error", {})
            if isinstance(error_obj, dict):
                return error_obj.get("message", response.text)
    except Exception:
        # JSON parsing failed or unexpected format
        pass

    # Fallback to raw response text
    return response.text
