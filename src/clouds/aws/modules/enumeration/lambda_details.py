import json
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def _find_cached_lambda(session_mgr: AWSSessionManager, function_name: str) -> Optional[Dict[str, Any]]:
    session_name = session_mgr.current_session
    if not session_name:
        return None
    lambdas: List[Dict[str, Any]] = (
        session_mgr.enumerated_data.get(session_name, {}).get("lambda_functions", [])
        if session_name in session_mgr.enumerated_data
        else []
    )
    for fn in lambdas:
        if fn.get("FunctionName") == function_name:
            return fn
    return None


def describe_lambda_function(
    session_mgr: AWSSessionManager,
    function_name: Optional[str] = None,
    region: Optional[str] = None,
) -> None:
    """
    Describe detailed information for a specific Lambda function:
    - GetFunction (Configuration + Code + Environment)
    - Uses cache from 'lambda_functions' when available for quick metadata.

    Args:
        function_name: Lambda function name or ARN.
        region: Override region (default: session's default region).
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not function_name:
        function_name = Prompt.ask("[cyan]Lambda function name[/cyan]")

    effective_region = region or session_mgr.default_region
    aws_sess = session_mgr.get_boto3_session()
    lambda_client = aws_sess.client("lambda", region_name=effective_region)

    console.print(f"[bold blue]🔍 Fetching details for Lambda function: {function_name} [{effective_region}][/bold blue]")

    try:
        resp = lambda_client.get_function(FunctionName=function_name)  # GetFunction[web:103][web:109]
    except Exception as e:
        console.print(f"[red]Failed to get Lambda function: {str(e)}[/red]")
        console.print("[yellow]Ensure Lambda:GetFunction permission and correct name.[/yellow]")
        return

    config: Dict[str, Any] = resp.get("Configuration", {})
    code: Dict[str, Any] = resp.get("Code", {})
    env: Dict[str, Any] = config.get("Environment", {}).get("Variables", {})

    cached = _find_cached_lambda(session_mgr, function_name)

    # Metadata table
    meta = Table(title=f"Lambda Metadata - {function_name}")
    meta.add_column("Field", style="cyan")
    meta.add_column("Value")
    meta.add_row("FunctionName", config.get("FunctionName", function_name))
    meta.add_row("FunctionArn", config.get("FunctionArn", ""))
    meta.add_row("Runtime", config.get("Runtime", ""))
    meta.add_row("Role", config.get("Role", ""))
    meta.add_row("Handler", config.get("Handler", ""))
    meta.add_row("LastModified", config.get("LastModified", ""))
    meta.add_row("Timeout", str(config.get("Timeout", "")))
    meta.add_row("MemorySize", str(config.get("MemorySize", "")))
    vpc_cfg = config.get("VpcConfig", {})
    meta.add_row("VpcId", vpc_cfg.get("VpcId", ""))
    meta.add_row("Subnets", ", ".join(vpc_cfg.get("SubnetIds", [])) or "–")
    meta.add_row("SecurityGroups", ", ".join(vpc_cfg.get("SecurityGroupIds", [])) or "–")
    meta.add_row("CodeSize", str(config.get("CodeSize", "")))
    meta.add_row("CodeLocation", code.get("Location", "")[:120] + ("..." if code.get("Location", "") and len(code["Location"]) > 120 else ""))
    if cached is not None:
        meta.add_row("CachedEventSources", str(len(cached.get("EventSources", []))))
    console.print(meta)

    # Ask if user wants to see env vars
    if env:
        console.print(
            "[bold yellow]⚠️ Environment variables may contain secrets "
            "(tokens, passwords, connection strings).[/bold yellow]"
        )
        if Confirm.ask("Show environment variables?"):
            env_table = Table(title="Lambda Environment Variables")
            env_table.add_column("Name", style="cyan")
            env_table.add_column("Value")
            for k, v in env.items():
                env_table.add_row(k, str(v))
            console.print(env_table)
    else:
        console.print("[yellow]No environment variables defined for this function.[/yellow]")

    # Save last viewed lambda details in session data (optional, for future features)
    session_mgr.save_enumeration_data(
        "lambda_last_details",
        {
            "FunctionName": function_name,
            "Configuration": config,
            "Code": {"Location": code.get("Location", ""), "RepositoryType": code.get("RepositoryType", "")},
            "Environment": env,
        },
    )

    console.print(
        "[green]Lambda details stored under key 'lambda_last_details' in session data.[/green]"
    )
