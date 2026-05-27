"""
WebSocket message types and protocol definitions.
"""

from enum import Enum
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict
import json


class MessageType(str, Enum):
    """WebSocket message types for CLI <-> Web communication."""

    # Session Management
    SESSION_CREATE = "session.create"
    SESSION_LIST = "session.list"
    SESSION_SWITCH = "session.switch"
    SESSION_DELETE = "session.delete"
    SESSION_CLEAR_ALL = "session.clear_all"

    # Lateral Movement
    ASSUME_ROLE = "lateral.assume_role"

    # Credential Configuration
    CREDS_SET_KEYS = "creds.set_keys"
    CREDS_SET_SSO_PROFILE = "creds.set_sso_profile"
    CREDS_SET_SSO_INTERACTIVE = "creds.set_sso_interactive"
    CREDS_WHOAMI = "creds.whoami"

    # Region/Project Configuration
    SET_REGION = "session.set_region"
    SET_PROJECT = "session.set_project"

    # Module Execution
    MODULE_RUN = "module.run"
    MODULE_OUTPUT = "module.output"
    MODULE_PROGRESS = "module.progress"
    MODULE_COMPLETE = "module.complete"
    MODULE_ERROR = "module.error"

    # Graph Updates
    GRAPH_NODE_ADD = "graph.node.add"
    GRAPH_NODE_UPDATE = "graph.node.update"
    GRAPH_EDGE_ADD = "graph.edge.add"
    GRAPH_UPDATE = "graph.update"
    GRAPH_SYNC = "graph.sync"
    GRAPH_CLEAR = "graph.clear"

    # Status
    STATUS = "status"
    ERROR = "error"
    SUCCESS = "success"

    # Connection
    PING = "ping"
    PONG = "pong"


@dataclass
class WebSocketMessage:
    """Message sent from Web -> CLI."""

    type: str
    payload: Dict[str, Any]
    request_id: Optional[str] = None

    def to_json(self) -> str:
        """Convert message to JSON string."""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> 'WebSocketMessage':
        """Parse message from JSON string."""
        parsed = json.loads(data)
        return cls(**parsed)


@dataclass
class WebSocketResponse:
    """Response sent from CLI -> Web."""

    type: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    request_id: Optional[str] = None

    def to_json(self) -> str:
        """Convert response to JSON string."""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> 'WebSocketResponse':
        """Parse response from JSON string."""
        parsed = json.loads(data)
        return cls(**parsed)


def create_success_response(
    message_type: str,
    data: Dict[str, Any],
    request_id: Optional[str] = None
) -> WebSocketResponse:
    """Create a success response."""
    return WebSocketResponse(
        type=message_type,
        success=True,
        data=data,
        request_id=request_id
    )


def create_error_response(
    message_type: str,
    error: str,
    request_id: Optional[str] = None
) -> WebSocketResponse:
    """Create an error response."""
    return WebSocketResponse(
        type=message_type,
        success=False,
        error=error,
        request_id=request_id
    )
