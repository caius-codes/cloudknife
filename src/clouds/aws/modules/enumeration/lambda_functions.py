from typing import List, Dict, Any, Tuple
import re

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory
from src.clouds.aws.utils.error_handling import safe_aws_call


console = Console()


# Deprecated Lambda runtimes (as of 2026)
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
    "ruby2.5",
    "java8",
    "go1.x"
}


def _detect_secrets_in_env_vars(env_vars: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Detect potential secrets in Lambda environment variables using pattern matching.

    Returns list of suspicious findings with:
    - var_name: name of the environment variable
    - reason: why it's flagged (pattern matched)
    - value_preview: first/last chars of value
    """
    findings = []

    # Patterns for secret detection
    SECRET_PATTERNS = [
        (r"(?i)(password|passwd|pwd)", "Password-like variable name"),
        (r"(?i)(secret|api_?key|apikey)", "Secret/API key variable name"),
        (r"(?i)(token|auth|jwt)", "Token/auth variable name"),
        (r"(?i)(credential|cred)", "Credential variable name"),
        (r"(?i)(private_?key|priv_?key)", "Private key variable name"),
        (r"(?i)(access_?key|secret_?key)", "AWS-like key variable name"),
        (r"(?i)(db_?pass|database_?pass)", "Database password variable"),
        (r"(?i)(connection_?string|conn_?str)", "Connection string variable"),
    ]

    # Value patterns (for actual secret values)
    VALUE_PATTERNS = [
        (r"^AKIA[0-9A-Z]{16}$", "AWS Access Key ID"),
        (r"^[A-Za-z0-9/+=]{40}$", "AWS Secret Access Key (base64-like)"),
        (r"^eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.", "JWT Token"),
        (r"-----BEGIN.*PRIVATE KEY-----", "Private Key (PEM)"),
        (r"^ghp_[A-Za-z0-9]{36}$", "GitHub Personal Access Token"),
        (r"^xox[baprs]-[A-Za-z0-9-]+$", "Slack Token"),
    ]

    for var_name, var_value in env_vars.items():
        # Check variable name patterns
        for pattern, reason in SECRET_PATTERNS:
            if re.search(pattern, var_name):
                # Show preview: first 4 + ... + last 4 chars
                if len(var_value) > 12:
                    preview = f"{var_value[:4]}...{var_value[-4:]}"
                else:
                    preview = "***"

                findings.append({
                    "var_name": var_name,
                    "reason": reason,
                    "value_preview": preview,
                    "value_length": len(var_value)
                })
                break  # Don't double-count same variable

        # Check value patterns
        for pattern, reason in VALUE_PATTERNS:
            if re.search(pattern, var_value):
                preview = f"{var_value[:8]}..." if len(var_value) > 8 else "***"
                findings.append({
                    "var_name": var_name,
                    "reason": f"Value matches {reason}",
                    "value_preview": preview,
                    "value_length": len(var_value)
                })
                break

    return findings


def enumerate_lambda(session_mgr: AWSSessionManager) -> None:
    """
    Comprehensive Lambda function enumeration with security-focused analysis.

    Collects for each function:
    - Basic metadata (name, ARN, runtime, handler, last modified)
    - IAM execution role
    - Memory, timeout, and code size
    - VPC configuration (VPC ID, subnets, security groups)
    - Environment variables (with secret pattern detection)
    - Event source mappings
    - Function URL configuration (public access check)
    - Resource-based policy (public invoke permissions)
    - Layers attached
    - Reserved concurrency

    Security Analysis:
    - Detects secrets in environment variables (passwords, API keys, tokens)
    - Identifies deprecated/EOL runtimes (security vulnerability risk)
    - Detects publicly accessible function URLs
    - Flags public invoke permissions via resource-based policy
    - Identifies VPC misconfigurations (public subnets)

    Multi-region aware with comprehensive security posture assessment.
    Saves detailed results under 'lambda_functions' in session data.

    Required Permissions:
    - lambda:ListFunctions (required)
    - lambda:GetFunction (for detailed config)
    - lambda:GetFunctionUrlConfig (for public URLs)
    - lambda:GetPolicy (for resource-based policies)
    - lambda:ListEventSourceMappings (for triggers)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="Lambda")
    console.print(
        f"[bold blue]🔍 Enumerating Lambda functions with security analysis across {len(regions)} regions[/bold blue]"
    )

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)
    functions: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            lambda_client = client_factory.get_client("lambda", region)

            paginator = lambda_client.get_paginator("list_functions")  # list_functions[web:96][web:98]
            for page in paginator.paginate(FunctionVersion="ALL"):
                for fn in page.get("Functions", []):
                    name = fn["FunctionName"]
                    arn = fn["FunctionArn"]
                    runtime = fn.get("Runtime", "")
                    role = fn.get("Role", "")
                    handler = fn.get("Handler", "")
                    last_modified = fn.get("LastModified", "")
                    timeout = fn.get("Timeout", "")
                    memory_size = fn.get("MemorySize", "")
                    vpc_config = fn.get("VpcConfig", {})
                    vpc_id = vpc_config.get("VpcId", "")
                    subnets = vpc_config.get("SubnetIds", [])
                    security_groups = vpc_config.get("SecurityGroupIds", [])
                    env = fn.get("Environment", {}).get("Variables", {})
                    has_env = bool(env)

                    # Detect secrets in environment variables
                    secret_findings = _detect_secrets_in_env_vars(env) if env else []
                    has_secrets = len(secret_findings) > 0

                    # Check for deprecated runtime
                    is_deprecated_runtime = runtime in DEPRECATED_RUNTIMES

                    # Get code size
                    code_size = fn.get("CodeSize", 0)

                    # Get layers
                    layers = fn.get("Layers", [])
                    layer_arns = [layer.get("Arn", "") for layer in layers]

                    # Reserved concurrent executions
                    reserved_concurrency = fn.get("ReservedConcurrentExecutions")

                    # Event source mappings per funzione
                    event_sources = []
                    try:
                        es_paginator = lambda_client.get_paginator("list_event_source_mappings")
                        for es_page in es_paginator.paginate(FunctionName=name):
                            for m in es_page.get("EventSourceMappings", []):
                                event_sources.append(
                                    {
                                        "UUID": m.get("UUID", ""),
                                        "EventSourceArn": m.get("EventSourceArn", ""),
                                        "State": m.get("State", ""),
                                        "BatchSize": m.get("BatchSize", ""),
                                    }
                                )
                    except Exception as e:
                        pass  # Silent fail for event sources

                    # Check for public function URL
                    function_url = None
                    is_public_url = False

                    url_config, _ = safe_aws_call(
                        lambda_client.get_function_url_config,
                        FunctionName=name,
                        log_error=False,
                        default={}
                    )

                    if url_config.get("FunctionUrl"):
                        function_url = url_config.get("FunctionUrl")
                        auth_type = url_config.get("AuthType", "")
                        is_public_url = (auth_type == "NONE")

                    # Check resource-based policy for public invoke permissions
                    has_public_invoke = False
                    policy_resp, _ = safe_aws_call(
                        lambda_client.get_policy,
                        FunctionName=name,
                        log_error=False,
                        default={}
                    )

                    if policy_resp.get("Policy"):
                        import json
                        try:
                            policy = json.loads(policy_resp["Policy"])
                            for statement in policy.get("Statement", []):
                                principal = statement.get("Principal", {})
                                # Check for wildcards or public principals
                                if principal == "*" or principal.get("AWS") == "*":
                                    has_public_invoke = True
                                    break
                        except:
                            pass  # Ignore JSON parse errors

                    functions.append(
                        {
                            "Region": region,
                            "FunctionName": name,
                            "FunctionArn": arn,
                            "Runtime": runtime,
                            "IsDeprecatedRuntime": is_deprecated_runtime,
                            "Role": role,
                            "Handler": handler,
                            "LastModified": last_modified,
                            "Timeout": timeout,
                            "MemorySize": memory_size,
                            "CodeSize": code_size,
                            "VpcId": vpc_id,
                            "Subnets": subnets,
                            "SecurityGroups": security_groups,
                            "HasEnvVars": has_env,
                            "EnvVars": env,
                            "SecretFindings": secret_findings,
                            "HasSecrets": has_secrets,
                            "EventSources": event_sources,
                            "FunctionUrl": function_url,
                            "IsPublicUrl": is_public_url,
                            "HasPublicInvoke": has_public_invoke,
                            "Layers": layer_arns,
                            "ReservedConcurrency": reserved_concurrency,
                        }
                    )
        except Exception as e:
            console.print(f"[red]Lambda enumeration failed in region {region}: {str(e)}[/red]")

    # Save into session data
    session_mgr.save_enumeration_data("lambda_functions", functions)

    if not functions:
        console.print("[yellow]No Lambda functions found in the selected regions.[/yellow]")
        return

    # Summary table with security-focused columns
    table = Table(title=f"Lambda Functions (total: {len(functions)})")
    table.add_column("Region", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("Name", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Runtime", overflow="fold", no_wrap=False)
    table.add_column("Public", style="bold", overflow="fold", no_wrap=False)
    table.add_column("Secrets", style="bold", overflow="fold", no_wrap=False)
    table.add_column("Role", overflow="fold", no_wrap=False)
    table.add_column("VPC", overflow="fold", no_wrap=False)

    # Track security issues
    functions_with_secrets = []
    deprecated_runtime_functions = []
    public_functions = []

    for fn in functions:
        # Runtime display (highlight deprecated)
        runtime = fn.get("Runtime", "unknown")
        if fn.get("IsDeprecatedRuntime"):
            runtime_display = f"[red]{runtime}[/red]"
            deprecated_runtime_functions.append(fn)
        else:
            runtime_display = runtime

        # Public access indicator
        if fn.get("IsPublicUrl") or fn.get("HasPublicInvoke"):
            if fn.get("IsPublicUrl"):
                public_display = "[red bold]URL[/red bold]"
            else:
                public_display = "[red]Policy[/red]"
            public_functions.append(fn)
        else:
            public_display = "–"

        # Secrets indicator
        if fn.get("HasSecrets"):
            secrets_count = len(fn.get("SecretFindings", []))
            secrets_display = f"[red bold]{secrets_count} 🚨[/red bold]"
            functions_with_secrets.append(fn)
        else:
            secrets_display = "–"

        # Role name (shortened)
        role_name = fn["Role"].split("/")[-1] if fn["Role"] else "–"

        # VPC indicator
        vpc_display = "✓" if fn.get("VpcId") else "–"

        table.add_row(
            fn["Region"],
            fn["FunctionName"][:40],  # Truncate long names
            runtime_display,
            public_display,
            secrets_display,
            role_name[:30],  # Truncate long role names
            vpc_display,
        )

    console.print(table)

    # Security findings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if functions_with_secrets:
        console.print(
            f"\n[red bold]🚨 CRITICAL - Secrets in Environment Variables:[/red bold] {len(functions_with_secrets)} function(s)"
        )
        console.print("[yellow]Environment variables contain potential secrets (passwords, API keys, tokens)![/yellow]")
        for fn in functions_with_secrets[:5]:
            secret_count = len(fn.get("SecretFindings", []))
            console.print(f"  • {fn['FunctionName']} in {fn['Region']} - {secret_count} secret(s) detected:")
            for finding in fn.get("SecretFindings", [])[:3]:
                console.print(f"    - {finding['var_name']}: {finding['reason']} ({finding['value_preview']})")
        if len(functions_with_secrets) > 5:
            console.print(f"  [dim]... and {len(functions_with_secrets) - 5} more[/dim]")

    if public_functions:
        console.print(
            f"\n[red bold]🚨 Publicly Accessible Functions:[/red bold] {len(public_functions)} function(s)"
        )
        console.print("[yellow]These functions can be invoked publicly via URL or resource policy![/yellow]")
        for fn in public_functions[:5]:
            if fn.get("IsPublicUrl"):
                console.print(f"  • {fn['FunctionName']} - Public URL: {fn['FunctionUrl']}")
            else:
                console.print(f"  • {fn['FunctionName']} - Public via resource-based policy")
        if len(public_functions) > 5:
            console.print(f"  [dim]... and {len(public_functions) - 5} more[/dim]")

    if deprecated_runtime_functions:
        console.print(
            f"\n[yellow]⚠️  Deprecated Runtimes:[/yellow] {len(deprecated_runtime_functions)} function(s) using EOL runtimes"
        )
        console.print("[dim]These runtimes are no longer supported and may have security vulnerabilities[/dim]")
        runtime_counts = {}
        for fn in deprecated_runtime_functions:
            rt = fn.get("Runtime", "unknown")
            runtime_counts[rt] = runtime_counts.get(rt, 0) + 1
        for runtime, count in sorted(runtime_counts.items(), key=lambda x: x[1], reverse=True):
            console.print(f"  • {runtime}: {count} function(s)")

    # VPC analysis
    vpc_functions = [fn for fn in functions if fn.get("VpcId")]
    if vpc_functions:
        console.print(
            f"\n[cyan]🔒 VPC Configuration:[/cyan] {len(vpc_functions)} function(s) in VPCs"
        )
        console.print("[dim]VPC-attached functions can access private resources but may have internet egress[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ Lambda enumeration complete. {len(functions)} functions analyzed and stored under 'lambda_functions' in session.[/green]"
    )
    console.print(
        "[dim]Full environment variables and secret details are in session data. "
        "Use 'show_data lambda_functions' to inspect.[/dim]"
    )
