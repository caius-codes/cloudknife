"""
Helper methods for creating GCP IAM graph nodes and relationships.

These methods are extracted to keep gcp_handler.py manageable.
"""

from typing import Set, Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


async def create_category_nodes(handler) -> Dict[str, str]:
    """
    Create category nodes for organizing IAM entities.

    Returns a dict mapping category type to node ID:
    {
        'users': 'gcp-iam-users-{session_id}',
        'groups': 'gcp-iam-groups-{session_id}',
        'roles': 'gcp-iam-roles-{session_id}',
        'service_accounts': 'gcp-iam-sa-{session_id}'
    }
    """
    logger.info("[GCP IAM] Creating category nodes")

    category_nodes = {}

    # Users category
    users_node_id = f"gcp-iam-users-{handler.current_session_id}"
    category_nodes['users'] = users_node_id
    await handler._add_or_update_node({
        'id': users_node_id,
        'type': 'gcp-iam-users',
        'label': '👤 Users',
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': None,
        'data': {
            'category': 'users',
            'is_category': True,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 1,
    })

    # Create edge: session → users category
    if handler.current_session_id:
        await handler._add_edge({
            'id': f"{handler.current_session_id}-owns-{users_node_id}",
            'source': handler.current_session_id,
            'target': users_node_id,
            'type': 'owns',
            'discoveredBy': [handler.current_session_id],
        })

    # Groups category
    groups_node_id = f"gcp-iam-groups-{handler.current_session_id}"
    category_nodes['groups'] = groups_node_id
    await handler._add_or_update_node({
        'id': groups_node_id,
        'type': 'gcp-iam-groups',
        'label': '👥 Groups',
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': None,
        'data': {
            'category': 'groups',
            'is_category': True,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 1,
    })

    if handler.current_session_id:
        await handler._add_edge({
            'id': f"{handler.current_session_id}-owns-{groups_node_id}",
            'source': handler.current_session_id,
            'target': groups_node_id,
            'type': 'owns',
            'discoveredBy': [handler.current_session_id],
        })

    # Roles category
    roles_node_id = f"gcp-iam-roles-{handler.current_session_id}"
    category_nodes['roles'] = roles_node_id
    await handler._add_or_update_node({
        'id': roles_node_id,
        'type': 'gcp-iam-roles',
        'label': '🛡️ Roles',
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': None,
        'data': {
            'category': 'roles',
            'is_category': True,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 1,
    })

    if handler.current_session_id:
        await handler._add_edge({
            'id': f"{handler.current_session_id}-owns-{roles_node_id}",
            'source': handler.current_session_id,
            'target': roles_node_id,
            'type': 'owns',
            'discoveredBy': [handler.current_session_id],
        })

    # Service Accounts category
    sa_node_id = f"gcp-iam-sa-{handler.current_session_id}"
    category_nodes['service_accounts'] = sa_node_id
    await handler._add_or_update_node({
        'id': sa_node_id,
        'type': 'gcp-iam-service-accounts',
        'label': '⚙️ Service Accounts',
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': None,
        'data': {
            'category': 'service_accounts',
            'is_category': True,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 1,
    })

    if handler.current_session_id:
        await handler._add_edge({
            'id': f"{handler.current_session_id}-owns-{sa_node_id}",
            'source': handler.current_session_id,
            'target': sa_node_id,
            'type': 'owns',
            'discoveredBy': [handler.current_session_id],
        })

    logger.info(f"[GCP IAM] Created {len(category_nodes)} category nodes")
    return category_nodes


async def create_nodes_from_project_policies(
    handler,
    iam_data: dict,
    created_users: Set[str],
    created_groups: Set[str],
    created_roles: Set[str],
    created_projects: Set[str],
    category_nodes: Dict[str, str]
) -> None:
    """Process project-level IAM policies to create nodes and bindings."""
    project_policies = iam_data.get('project_policies', [])
    logger.info(f"[GCP IAM] Processing {len(project_policies)} project policies")

    for policy in project_policies:
        project = policy['project']
        bindings = policy.get('bindings', [])

        logger.debug(f"[GCP IAM] Project {project}: {len(bindings)} bindings")

        for binding in bindings:
            role = binding['role']
            members = binding.get('members', [])
            condition = binding.get('condition')

            # Create role node if not exists
            if role not in created_roles:
                await _create_role_node(
                    handler, role, project, created_roles, created_projects, category_nodes
                )

            # Create nodes for each member and bind to role
            for member in members:
                await _create_member_and_binding(
                    handler,
                    member,
                    role,
                    project,
                    condition,
                    created_users,
                    created_groups,
                    category_nodes
                )


async def create_nodes_from_gcloud_policies(
    handler,
    iam_data: dict,
    created_users: Set[str],
    created_groups: Set[str],
    created_roles: Set[str],
    created_projects: Set[str],
    category_nodes: Dict[str, str]
) -> None:
    """Process gcloud-fetched policies for additional detail."""
    gcloud_policies = iam_data.get('gcloud_policies', [])
    logger.info(f"[GCP IAM] Processing {len(gcloud_policies)} gcloud policies")

    for gcloud_data in gcloud_policies:
        project = gcloud_data['project']
        policy = gcloud_data.get('policy', {})
        bindings = policy.get('bindings', [])

        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])
            condition = binding.get('condition')

            # Create role node if not exists
            if role and role not in created_roles:
                await _create_role_node(
                    handler, role, project, created_roles, created_projects, category_nodes
                )

            # Create nodes for each member and bind to role
            for member in members:
                await _create_member_and_binding(
                    handler,
                    member,
                    role,
                    project,
                    condition,
                    created_users,
                    created_groups,
                    category_nodes
                )


async def create_custom_role_nodes(
    handler,
    iam_data: dict,
    created_roles: Set[str],
    created_projects: Set[str],
    category_nodes: Dict[str, str]
) -> None:
    """Create nodes for custom IAM roles."""
    custom_roles = iam_data.get('custom_roles', [])
    logger.info(f"[GCP IAM] Creating {len(custom_roles)} custom role nodes")

    for role_data in custom_roles:
        role_name = role_data['name']
        project = role_data['project']

        # Normalize role name to ensure correct format
        if role_name.startswith('projects/') and '/roles/' not in role_name:
            parts = role_name.split('/')
            if len(parts) == 3:
                role_name = f"{parts[0]}/{parts[1]}/roles/{parts[2]}"
        elif role_name.startswith('organizations/') and '/roles/' not in role_name:
            parts = role_name.split('/')
            if len(parts) == 3:
                role_name = f"{parts[0]}/{parts[1]}/roles/{parts[2]}"

        if role_name in created_roles:
            continue

        # Extract short name
        role_short = role_name.split('/')[-1] if '/' in role_name else role_name

        node_id = f"gcp-role-{role_short}"
        created_roles.add(role_name)
        created_projects.add(project)

        node = {
            'id': node_id,
            'type': 'gcp-role',
            'label': role_data.get('title') or role_short,
            'provider': 'gcp',
            'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
            'parentId': category_nodes.get('roles'),  # Set parent to Roles category
            'data': {
                'role_name': role_name,
                'role_short': role_short,
                'project': project,
                'custom': True,
                'title': role_data.get('title'),
                'description': role_data.get('description'),
                'stage': role_data.get('stage'),
                'permissions': role_data.get('permissions', []),
                'permission_count': len(role_data.get('permissions', [])),
                'deleted': role_data.get('deleted', False),
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'gcp_enumerate_iam',
                'fullName': role_name,
            },
            'level': 2,  # Child level (under category)
        }

        await handler._add_or_update_node(node)

        # Create edge: Roles category -> custom role
        roles_category_id = category_nodes.get('roles')
        if roles_category_id:
            await handler._add_edge({
                'id': f"{roles_category_id}-contains-{node_id}",
                'source': roles_category_id,
                'target': node_id,
                'type': 'contains',
                'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
            })


async def create_nodes_from_org_policy(
    handler,
    iam_data: dict,
    created_users: Set[str],
    created_groups: Set[str],
    created_roles: Set[str],
    category_nodes: Dict[str, str]
) -> None:
    """Process organization-level IAM policy."""
    org_policy = iam_data.get('org_policy')
    if not org_policy:
        return

    logger.info("[GCP IAM] Processing organization policy")

    organization = org_policy['organization']
    bindings = org_policy.get('bindings', [])

    for binding in bindings:
        role = binding['role']
        members = binding.get('members', [])
        condition = binding.get('condition')

        # Create role node if not exists
        if role not in created_roles:
            await _create_role_node(handler, role, 'org', created_roles, set(), category_nodes)

        # Create nodes for each member and bind to role
        for member in members:
            await _create_member_and_binding(
                handler,
                member,
                role,
                'org',
                condition,
                created_users,
                created_groups,
                category_nodes,
                organization_scope=True
            )


# ==================== Private Helper Functions ====================


async def _create_role_node(
    handler,
    role_name: str,
    project: str,
    created_roles: Set[str],
    created_projects: Set[str],
    category_nodes: Dict[str, str]
) -> None:
    """Create a role node."""
    # Normalize role name to ensure correct format
    # GCP API sometimes returns custom roles without /roles/ in the path
    if role_name.startswith('projects/') and '/roles/' not in role_name:
        # Format: projects/PROJECT/CustomRole -> projects/PROJECT/roles/CustomRole
        parts = role_name.split('/')
        if len(parts) == 3:  # projects/PROJECT/ROLE
            role_name = f"{parts[0]}/{parts[1]}/roles/{parts[2]}"
    elif role_name.startswith('organizations/') and '/roles/' not in role_name:
        # Format: organizations/ORG/CustomRole -> organizations/ORG/roles/CustomRole
        parts = role_name.split('/')
        if len(parts) == 3:  # organizations/ORG/ROLE
            role_name = f"{parts[0]}/{parts[1]}/roles/{parts[2]}"

    if role_name in created_roles:
        return

    # Extract short name and determine if predefined
    role_short = role_name.replace('roles/', '')
    is_predefined = role_name.startswith('roles/')

    # Determine privilege level
    is_high_privilege = any(x in role_name.lower() for x in ['owner', 'admin', 'editor'])

    node_id = f"gcp-role-{role_short}"
    created_roles.add(role_name)
    if project != 'org':
        created_projects.add(project)

    node = {
        'id': node_id,
        'type': 'gcp-role',
        'label': role_short,
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': category_nodes.get('roles'),  # Set parent to Roles category
        'data': {
            'role_name': role_name,
            'role_short': role_short,
            'project': project if project != 'org' else None,
            'custom': not is_predefined,
            'predefined': is_predefined,
            'high_privilege': is_high_privilege,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
            'fullName': role_name,
        },
        'level': 2,  # Child level (under category)
    }

    await handler._add_or_update_node(node)

    # Create edge: Roles category -> role
    roles_category_id = category_nodes.get('roles')
    if roles_category_id:
        await handler._add_edge({
            'id': f"{roles_category_id}-contains-{node_id}",
            'source': roles_category_id,
            'target': node_id,
            'type': 'contains',
            'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        })


async def _create_member_and_binding(
    handler,
    member: str,
    role: str,
    project: str,
    condition: Dict[str, Any] | None,
    created_users: Set[str],
    created_groups: Set[str],
    category_nodes: Dict[str, str],
    organization_scope: bool = False
) -> None:
    """Create a member node (user/group) and its binding to a role."""
    member_type, member_id = _parse_member(member)

    # Skip special members like allUsers, allAuthenticatedUsers
    if member_type in ['allUsers', 'allAuthenticatedUsers', 'domain']:
        # Could create special nodes for these if needed
        logger.debug(f"[GCP IAM] Skipping special member: {member}")
        return

    node_id = None

    if member_type == 'user':
        if member_id not in created_users:
            node_id = await _create_user_node(handler, member_id, created_users, category_nodes)
        else:
            node_id = f"gcp-user-{member_id}"

    elif member_type == 'group':
        if member_id not in created_groups:
            node_id = await _create_group_node(handler, member_id, created_groups, category_nodes)
        else:
            node_id = f"gcp-group-{member_id}"

    elif member_type == 'serviceAccount':
        # Service account should already exist from _create_service_account_nodes
        node_id = f"gcp-sa-{member_id}"

    if not node_id:
        return

    # Create binding edge: member -> role
    role_short = role.replace('roles/', '')
    role_node_id = f"gcp-role-{role_short}"

    edge_id = f"{node_id}-has-{role_node_id}"
    if project != 'org':
        edge_id += f"-{project}"

    edge = {
        'id': edge_id,
        'source': node_id,
        'target': role_node_id,
        'type': 'has-role',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'data': {
            'project': project if project != 'org' else None,
            'conditional': condition is not None,
            'condition_title': condition.get('title') if condition else None,
            'condition_expression': condition.get('expression') if condition else None,
            'organization_scope': organization_scope,
        }
    }

    await handler._add_edge(edge)


async def _create_user_node(
    handler,
    user_email: str,
    created_users: Set[str],
    category_nodes: Dict[str, str]
) -> str:
    """Create a user node."""
    node_id = f"gcp-user-{user_email}"
    created_users.add(user_email)

    # Extract name from email (before @)
    display_name = user_email.split('@')[0]

    node = {
        'id': node_id,
        'type': 'gcp-user',
        'label': display_name,
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': category_nodes.get('users'),  # Set parent to Users category
        'data': {
            'email': user_email,
            'domain': user_email.split('@')[1] if '@' in user_email else None,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 2,  # Child level (under category)
    }

    await handler._add_or_update_node(node)

    # Create edge: Users category -> user
    users_category_id = category_nodes.get('users')
    if users_category_id:
        await handler._add_edge({
            'id': f"{users_category_id}-contains-{node_id}",
            'source': users_category_id,
            'target': node_id,
            'type': 'contains',
            'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        })

    return node_id


async def _create_group_node(
    handler,
    group_email: str,
    created_groups: Set[str],
    category_nodes: Dict[str, str]
) -> str:
    """Create a group node."""
    node_id = f"gcp-group-{group_email}"
    created_groups.add(group_email)

    # Extract name from email (before @)
    display_name = group_email.split('@')[0]

    node = {
        'id': node_id,
        'type': 'gcp-group',
        'label': display_name,
        'provider': 'gcp',
        'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        'parentId': category_nodes.get('groups'),  # Set parent to Groups category
        'data': {
            'email': group_email,
            'domain': group_email.split('@')[1] if '@' in group_email else None,
        },
        'metadata': {
            'discoveredAt': datetime.now().isoformat(),
            'moduleUsed': 'gcp_enumerate_iam',
        },
        'level': 2,  # Child level (under category)
    }

    await handler._add_or_update_node(node)

    # Create edge: Groups category -> group
    groups_category_id = category_nodes.get('groups')
    if groups_category_id:
        await handler._add_edge({
            'id': f"{groups_category_id}-contains-{node_id}",
            'source': groups_category_id,
            'target': node_id,
            'type': 'contains',
            'discoveredBy': [handler.current_session_id] if handler.current_session_id else [],
        })

    return node_id


def _parse_member(member: str) -> tuple[str, str]:
    """
    Parse a member string into type and identifier.

    Examples:
        user:alice@example.com -> ('user', 'alice@example.com')
        serviceAccount:sa@project.iam.gserviceaccount.com -> ('serviceAccount', 'sa@project.iam.gserviceaccount.com')
        group:admins@example.com -> ('group', 'admins@example.com')
        allUsers -> ('allUsers', 'allUsers')
        domain:example.com -> ('domain', 'example.com')
    """
    if ':' not in member:
        # Special members like allUsers, allAuthenticatedUsers
        return (member, member)

    member_type, member_id = member.split(':', 1)
    return (member_type, member_id)
