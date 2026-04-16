"""
GCP Lateral Movement modules - alphabetically sorted.

Techniques for moving between identities and expanding access within GCP.
"""

# Alphabetically sorted imports
from .implicit_delegation import (
    find_delegation_chains,
    generate_access_token,
    generate_access_token_direct_api,
    generate_token_curl_command,
    impersonate_service_account,
    map_impersonation_graph,
)
from .jwt_impersonation import (
    apply_template,
    exchange_jwt_for_token,
    generate_signed_jwt,
    impersonate_with_jwt,
    show_jwt_templates,
)
from .sa_iam_policy import (
    get_sa_iam_policy,
    remove_sa_iam_binding,
    set_sa_iam_policy,
)
from .sa_key_creation import (
    create_sa_key,
    delete_sa_key,
    list_sa_keys,
)
from .sign_jwt import (
    sign_blob,
    sign_jwt,
    sign_jwt_batch,
    sign_jwt_for_access_token,
)

__all__ = [
    "apply_template",
    "create_sa_key",
    "delete_sa_key",
    "exchange_jwt_for_token",
    "find_delegation_chains",
    "generate_access_token",
    "generate_access_token_direct_api",
    "generate_signed_jwt",
    "generate_token_curl_command",
    "get_sa_iam_policy",
    "impersonate_service_account",
    "impersonate_with_jwt",
    "list_sa_keys",
    "map_impersonation_graph",
    "remove_sa_iam_binding",
    "set_sa_iam_policy",
    "show_jwt_templates",
    "sign_blob",
    "sign_jwt",
    "sign_jwt_batch",
    "sign_jwt_for_access_token",
]
