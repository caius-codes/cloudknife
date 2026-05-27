"""
Session Importer - Import CLI sessions and enumeration data into WebSocket server.

This module reads existing CloudKnife CLI sessions from disk and converts them
into the format expected by the WebSocket server, including graph nodes and edges.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

from src.core.session import get_cloudknife_home

logger = logging.getLogger(__name__)


# Mapping of enumeration types to graph node types
ENUMERATION_TYPE_MAP = {
    'iam_roles': 'aws-role',
    'iam_roles_simple': 'aws-role',
    'iam_users': 'aws-user',
    'iam_groups': 'aws-group',
    'lambda_functions': 'aws-lambda',
    'iam_policies': 'aws-policy',
    'secrets_manager': 'aws-secret',
    's3_buckets': 'aws-s3-bucket',
}


def get_node_id_prefix(enum_type: str) -> str:
    """Get the node ID prefix for a given enumeration type."""
    return {
        'iam_roles': 'role',
        'iam_roles_simple': 'role',
        'iam_users': 'user',
        'lambda_functions': 'lambda',
        'iam_groups': 'group',
        'iam_policies': 'policy',
        'secrets_manager': 'secret',
        's3_buckets': 's3',
    }.get(enum_type, 'resource')


def import_single_session(session_file: Path, cloud: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Import a single CLI session file.

    Args:
        session_file: Path to the session JSON file
        cloud: Cloud provider name (e.g., 'aws', 'gcp', 'azure')

    Returns:
        Tuple of (session_node, edges) or (None, []) if import fails
    """
    try:
        session_name = session_file.stem

        # Load session data
        session_data = _load_session_file(session_file)
        if not session_data:
            return None, []

        # Load enumeration data if exists
        enum_file = session_file.parent / f"{session_name}_enum.json"
        enum_data = _load_enumeration_file(enum_file) if enum_file.exists() else {}

        # Create session node
        session_node = _create_session_node(session_name, session_data, cloud)

        # Build graph from enumeration data
        edges = []
        if enum_data:
            nodes, edges = _build_graph_from_enumeration(
                session_name,
                session_data.get('session_id', session_name),
                enum_data,
                cloud
            )
            # Add enumerated nodes to graph (they'll be added by the caller)
            # For now, we only return the session node and edges to it

        logger.info(f"[SessionImporter] Imported single session: {session_name}")
        return session_node, edges

    except Exception as e:
        logger.error(f"[SessionImporter] Error importing session {session_file.name}: {e}", exc_info=True)
        return None, []


def import_cli_sessions(cloud: str) -> Dict[str, Any]:
    """
    Import all CLI sessions and enumeration data for a given cloud.

    Args:
        cloud: Cloud provider name (e.g., 'aws', 'gcp', 'azure')

    Returns:
        Dict containing:
        - sessions: List of session objects
        - nodes: List of graph nodes
        - edges: List of graph edges
    """
    logger.info(f"[SessionImporter] Starting import for cloud: {cloud}")

    sessions_dir = get_cloudknife_home() / "sessions" / cloud
    if not sessions_dir.exists():
        logger.warning(f"[SessionImporter] Sessions directory not found: {sessions_dir}")
        return {'sessions': [], 'nodes': [], 'edges': []}

    sessions = []
    all_nodes = []
    all_edges = []

    # Scan for all session files
    for session_file in sessions_dir.glob("*.json"):
        # Skip enumeration files and service account key files
        if session_file.stem.endswith("_enum") or session_file.stem.endswith("_key"):
            continue

        try:
            session_name = session_file.stem

            # Load session data
            session_data = _load_session_file(session_file)
            if not session_data:
                continue

            # Load enumeration data if exists
            enum_file = sessions_dir / f"{session_name}_enum.json"
            enum_data = _load_enumeration_file(enum_file) if enum_file.exists() else {}

            # Create session object
            session = _create_session_object(session_name, session_data, cloud)
            sessions.append(session)

            # Create session node
            session_node = _create_session_node(session_name, session_data, cloud)
            all_nodes.append(session_node)

            # Build graph from enumeration data
            if enum_data:
                nodes, edges = _build_graph_from_enumeration(
                    session_name,
                    session_data.get('session_id', session_name),
                    enum_data,
                    cloud
                )
                all_nodes.extend(nodes)
                all_edges.extend(edges)

            logger.info(f"[SessionImporter] Imported session: {session_name}")

        except Exception as e:
            logger.error(f"[SessionImporter] Error importing session {session_file.name}: {e}", exc_info=True)
            continue

    logger.info(f"[SessionImporter] Import complete - Sessions: {len(sessions)}, Nodes: {len(all_nodes)}, Edges: {len(all_edges)}")

    return {
        'sessions': sessions,
        'nodes': all_nodes,
        'edges': all_edges,
    }


def _load_session_file(path: Path) -> Optional[Dict[str, Any]]:
    """Load and parse a session JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning(f"[SessionImporter] Invalid session file format: {path.name}")
            return None
        return data
    except Exception as e:
        logger.error(f"[SessionImporter] Error loading session file {path.name}: {e}")
        return None


def _load_enumeration_file(path: Path) -> Optional[Dict[str, Any]]:
    """Load and parse an enumeration JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning(f"[SessionImporter] Invalid enumeration file format: {path.name}")
            return None
        return data
    except Exception as e:
        logger.error(f"[SessionImporter] Error loading enumeration file {path.name}: {e}")
        return None


def _create_session_object(session_name: str, session_data: Dict[str, Any], cloud: str) -> Dict[str, Any]:
    """Create a session object for the WebSocket server."""
    return {
        'id': session_data.get('session_id', session_name),
        'name': session_name,
        'cloud': cloud,
        'region': session_data.get('region', 'us-east-1'),
        'arn': session_data.get('arn', ''),
        'account': session_data.get('account', ''),
        'user_id': session_data.get('user_id', ''),
        'has_credentials': bool(session_data.get('access_key')),
    }


def _create_session_node(session_name: str, session_data: Dict[str, Any], cloud: str) -> Dict[str, Any]:
    """Create a graph node for a session."""
    # Build identity object matching whoami response format for each cloud provider
    identity = None
    metadata = {
        'discoveredAt': datetime.now().isoformat(),
        'moduleUsed': 'cli_import',
    }

    if cloud == 'aws' and session_data.get('arn'):
        # AWS identity
        identity = {
            'UserId': session_data.get('user_id', ''),
            'Account': session_data.get('account', ''),
            'Arn': session_data.get('arn', ''),
        }
        metadata['arn'] = session_data.get('arn', '')

    elif cloud == 'gcp' and session_data.get('service_account_email'):
        # GCP identity
        identity = {
            'auth_method': session_data.get('auth_method', ''),
            'project_id': session_data.get('project_id', ''),
            'service_account_email': session_data.get('service_account_email', ''),
        }
        metadata['project_id'] = session_data.get('project_id', '')
        metadata['service_account_email'] = session_data.get('service_account_email', '')
        metadata['auth_method'] = session_data.get('auth_method', '')

    # Use CLI's session_id as the node ID for consistency
    session_uuid = session_data.get('session_id', f'session-{session_name}')

    return {
        'id': session_uuid,  # UUID from CLI (e.g., "e7c68b0e-18a7-4de2-a7b7-986c2483ff4d")
        'type': f'{cloud}-session',
        'label': session_name,
        'provider': cloud,
        'discoveredBy': [session_uuid],
        'parentId': None,
        'data': {
            'sessionName': session_name,
            'sessionId': session_uuid,
            'identity': identity,  # Cloud-specific identity
            'createdAt': datetime.now().isoformat(),
        },
        'metadata': metadata,
        'level': 0,
    }


def _build_graph_from_enumeration(
    session_name: str,
    session_id: str,
    enum_data: Dict[str, Any],
    cloud: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Build graph nodes and edges from enumeration data.

    Args:
        session_name: Name of the session
        session_id: UUID of the session
        enum_data: Enumeration data dict
        cloud: Cloud provider

    Returns:
        Tuple of (nodes, edges)
    """
    nodes = []
    edges = []

    # Process each enumeration type
    for enum_type, resources in enum_data.items():
        if not isinstance(resources, list):
            continue

        node_type = ENUMERATION_TYPE_MAP.get(enum_type)
        if not node_type:
            logger.debug(f"[SessionImporter] Skipping unknown enumeration type: {enum_type}")
            continue

        id_prefix = get_node_id_prefix(enum_type)

        for resource in resources:
            try:
                node, edge = _create_resource_node_and_edge(
                    resource,
                    enum_type,
                    node_type,
                    id_prefix,
                    session_name,
                    session_id,
                    cloud
                )
                if node:
                    nodes.append(node)
                if edge:
                    edges.append(edge)
            except Exception as e:
                logger.error(f"[SessionImporter] Error creating node for {enum_type}: {e}")
                continue

    return nodes, edges


def _create_resource_node_and_edge(
    resource: Dict[str, Any],
    enum_type: str,
    node_type: str,
    id_prefix: str,
    session_name: str,
    session_id: str,
    cloud: str
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Create a graph node and edge for a discovered resource."""

    # Extract ARN or identifier (try both 'Arn' and 'ARN')
    arn = resource.get('Arn') or resource.get('ARN') or resource.get('FunctionArn')
    if not arn:
        logger.warning(f"[SessionImporter] Resource missing ARN: {resource}")
        return None, None

    # Extract label
    label = (
        resource.get('RoleName') or
        resource.get('UserName') or
        resource.get('GroupName') or
        resource.get('PolicyName') or
        resource.get('FunctionName') or
        resource.get('Name') or  # For secrets
        arn.split('/')[-1]
    )

    # Create node
    metadata = {
        'arn': arn,
        'discoveredAt': datetime.now().isoformat(),
        'moduleUsed': enum_type,
    }

    # Add region for secrets_manager and s3_buckets
    if enum_type == 'secrets_manager':
        metadata['region'] = resource.get('Region', '')
    elif enum_type == 's3_buckets':
        metadata['region'] = resource.get('Region', 'us-east-1')

    node = {
        'id': f'{id_prefix}-{arn}',
        'type': node_type,
        'label': label,
        'provider': cloud,
        'discoveredBy': [session_id],
        'parentId': f'session-{session_name}',
        'data': _extract_resource_data(resource, enum_type),
        'metadata': metadata,
        'level': 4 if enum_type == 'secrets_manager' else 1,
    }

    # Determine edge type based on resource type and assume status
    edge_label = 'discovered'
    edge_type = 'owns'

    # For IAM roles, check if they can be assumed
    if enum_type in ['iam_roles', 'iam_roles_simple']:
        assume_status = resource.get('AssumeStatus', 'UNKNOWN')
        if assume_status == 'ALLOWED':
            edge_label = 'can assume'
            edge_type = 'assume'
        elif assume_status == 'DENIED':
            edge_label = 'discovered'
            edge_type = 'owns'

    # Create edge (using session_id UUID as source instead of name-based ID)
    edge = {
        'id': f'edge-{session_id}-{arn}',
        'source': session_id,  # UUID from CLI
        'target': f'{id_prefix}-{arn}',
        'label': edge_label,
        'type': edge_type,
        'discoveredBy': [session_id],
    }

    return node, edge


def _extract_resource_data(resource: Dict[str, Any], enum_type: str) -> Dict[str, Any]:
    """Extract relevant data from a resource based on its type."""

    # Common fields
    data = {}

    if enum_type in ['iam_roles', 'iam_roles_simple']:
        data = {
            'roleName': resource.get('RoleName'),
            'roleArn': resource.get('Arn'),
            'createDate': resource.get('CreateDate', ''),
            'maxSessionDuration': resource.get('MaxSessionDuration', ''),
            'description': resource.get('Description', ''),
            'path': resource.get('Path', '/'),
            'assumeStatus': resource.get('AssumeStatus', 'UNKNOWN'),
            'isServiceRole': resource.get('IsServiceRole', False),
        }
    elif enum_type == 'iam_users':
        data = {
            'userName': resource.get('UserName'),
            'userArn': resource.get('Arn'),
            'userId': resource.get('UserId'),
            'createDate': resource.get('CreateDate', ''),
            'path': resource.get('Path', '/'),
        }
    elif enum_type == 'iam_groups':
        data = {
            'groupName': resource.get('GroupName'),
            'groupArn': resource.get('Arn'),
            'groupId': resource.get('GroupId'),
            'createDate': resource.get('CreateDate', ''),
            'path': resource.get('Path', '/'),
        }
    elif enum_type == 'lambda_functions':
        data = {
            'functionName': resource.get('FunctionName'),
            'functionArn': resource.get('FunctionArn'),
            'runtime': resource.get('Runtime'),
            'handler': resource.get('Handler'),
            'description': resource.get('Description', ''),
            'memorySize': resource.get('MemorySize'),
            'timeout': resource.get('Timeout'),
            'role': resource.get('Role'),
        }
    elif enum_type == 'secrets_manager':
        data = {
            'secretName': resource.get('Name'),
            'secretArn': resource.get('ARN'),
            'region': resource.get('Region'),
            'description': resource.get('Description', ''),
            'versionId': resource.get('VersionId', ''),
            'createdDate': resource.get('CreatedDate', ''),
            'lastChangedDate': resource.get('LastChangedDate', ''),
            'kmsKeyId': resource.get('KmsKeyId', ''),
            'rotationEnabled': resource.get('RotationEnabled', False),
        }
    elif enum_type == 's3_buckets':
        is_public = resource.get('PublicRead', False) or resource.get('PublicWrite', False)
        no_encryption = resource.get('Encryption', 'None') == 'None'
        bpa_disabled = not resource.get('BlockPublicAccessEnabled', False)

        data = {
            'bucketName': resource.get('Name'),
            'region': resource.get('Region', 'us-east-1'),
            'creationDate': resource.get('CreationDate', ''),
            'publicRead': resource.get('PublicRead', False),
            'publicWrite': resource.get('PublicWrite', False),
            'blockPublicAccessEnabled': resource.get('BlockPublicAccessEnabled', False),
            'encryption': resource.get('Encryption', 'None'),
            'versioning': resource.get('Versioning', 'Disabled'),
            'loggingEnabled': resource.get('LoggingEnabled', False),
            'websiteHosting': resource.get('WebsiteHosting', False),
            'isPublic': is_public,
            'isUnencrypted': no_encryption,
            'isBpaDisabled': bpa_disabled,
        }
    else:
        # Generic fallback
        data = resource.copy()

    return data
