from typing import Dict, Any, List

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions
from src.clouds.aws.utils.error_handling import categorize_error, AWSError, ErrorCategory
from src.clouds.aws.utils.parallel import RegionalExecutor

console = Console()


def _format_error_hint(error: AWSError) -> str:
    """Format error for display in summary table."""
    if error.category == ErrorCategory.AUTHORIZATION:
        return "missing permissions for this service"
    elif error.category == ErrorCategory.AUTHENTICATION:
        return "authentication failed"
    elif error.category == ErrorCategory.THROTTLING:
        return f"rate limited ({error.code})"
    elif error.category == ErrorCategory.NETWORK:
        return "network error"
    return f"aws error: {error.code}" if error.code else "unknown error"


def _enumerate_service_in_region(
    aws_sess,
    service_name: str,
    region: str,
    paginator_method: str,
    result_key: str
) -> int:
    """
    Generic helper to enumerate a service in a region using pagination.

    Args:
        aws_sess: Boto3 session
        service_name: AWS service name (e.g., 'ec2', 'lambda')
        region: AWS region
        paginator_method: Paginator method name (e.g., 'describe_instances')
        result_key: Key to extract results from response

    Returns:
        Count of resources found
    """
    client = aws_sess.client(service_name, region_name=region)
    paginator = client.get_paginator(paginator_method)
    count = 0

    for page in paginator.paginate():
        items = page.get(result_key, [])
        if service_name == "ec2" and result_key == "Reservations":
            # Special handling for EC2 Reservations
            for reservation in items:
                count += len(reservation.get("Instances", []))
        else:
            count += len(items)

    return count


def quick_enum(session_mgr: AWSSessionManager) -> None:
    """
    Lightweight multi-service overview:
    - EC2 instance count
    - Lambda functions count
    - DynamoDB tables count
    - ECR repositories count
    - Secrets Manager secrets count
    - Amazon MQ brokers count
    - IAM users, groups, policies (global)

    Uses only cheap list/describe calls with pagination.
    Now parallelized across regions for better performance.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    target_regions = resolve_regions(session_mgr, service_name="quick_enum")

    console.print(
        f"[bold blue]🔍 Running quick_enum across {len(target_regions)} regions[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    summary: List[Dict[str, Any]] = []

    # Create parallel executor for regional services
    executor = RegionalExecutor(max_workers=min(len(target_regions), 8), show_progress=True)

    # ---------- EC2 (parallelized) ----------
    def enumerate_ec2_region(region: str) -> int:
        """Count EC2 instances in a region."""
        return _enumerate_service_in_region(
            aws_sess, "ec2", region, "describe_instances", "Reservations"
        )

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_ec2_region,
        operation_name="EC2 Instances"
    )

    ec2_total = sum(result.get_successful_results())
    ec2_regions_with_data = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "ec2",
            "regions": ec2_regions_with_data,
            "count": ec2_total,
            "status": "OK" if ec2_total > 0 else "EMPTY",
            "hint": "enumerate_ec2" if ec2_total > 0 else "no resources found",
        })
    else:
        # All regions failed
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "ec2",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- Lambda (parallelized) ----------
    def enumerate_lambda_region(region: str) -> int:
        """Count Lambda functions in a region."""
        return _enumerate_service_in_region(
            aws_sess, "lambda", region, "list_functions", "Functions"
        )

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_lambda_region,
        operation_name="Lambda Functions"
    )

    lambda_total = sum(result.get_successful_results())
    lambda_regions = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "lambda",
            "regions": lambda_regions,
            "count": lambda_total,
            "status": "OK" if lambda_total > 0 else "EMPTY",
            "hint": "enumerate_lambda" if lambda_total > 0 else "no resources found",
        })
    else:
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "lambda",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- DynamoDB (parallelized) ----------
    def enumerate_dynamodb_region(region: str) -> int:
        """Count DynamoDB tables in a region."""
        return _enumerate_service_in_region(
            aws_sess, "dynamodb", region, "list_tables", "TableNames"
        )

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_dynamodb_region,
        operation_name="DynamoDB Tables"
    )

    ddb_total = sum(result.get_successful_results())
    ddb_regions = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "dynamodb",
            "regions": ddb_regions,
            "count": ddb_total,
            "status": "OK" if ddb_total > 0 else "EMPTY",
            "hint": "enumerate_dynamodb" if ddb_total > 0 else "no resources found",
        })
    else:
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "dynamodb",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- ECR (parallelized) ----------
    def enumerate_ecr_region(region: str) -> int:
        """Count ECR repositories in a region."""
        return _enumerate_service_in_region(
            aws_sess, "ecr", region, "describe_repositories", "repositories"
        )

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_ecr_region,
        operation_name="ECR Repositories"
    )

    ecr_total = sum(result.get_successful_results())
    ecr_regions = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "ecr",
            "regions": ecr_regions,
            "count": ecr_total,
            "status": "OK" if ecr_total > 0 else "EMPTY",
            "hint": "enumerate_ecr" if ecr_total > 0 else "no resources found",
        })
    else:
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "ecr",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- Secrets Manager (parallelized) ----------
    def enumerate_secrets_region(region: str) -> int:
        """Count Secrets Manager secrets in a region."""
        sm = aws_sess.client("secretsmanager", region_name=region)
        next_token = None
        count = 0
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = sm.list_secrets(**kwargs)
            count += len(resp.get("SecretList", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return count

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_secrets_region,
        operation_name="Secrets Manager"
    )

    secrets_total = sum(result.get_successful_results())
    secrets_regions = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "secretsmanager",
            "regions": secrets_regions,
            "count": secrets_total,
            "status": "OK" if secrets_total > 0 else "EMPTY",
            "hint": "enumerate_secrets" if secrets_total > 0 else "no resources found",
        })
    else:
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "secretsmanager",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- Amazon MQ (parallelized) ----------
    def enumerate_mq_region(region: str) -> int:
        """Count MQ brokers in a region."""
        return _enumerate_service_in_region(
            aws_sess, "mq", region, "list_brokers", "BrokerSummaries"
        )

    result = executor.execute(
        regions=target_regions,
        operation=enumerate_mq_region,
        operation_name="Amazon MQ"
    )

    mq_total = sum(result.get_successful_results())
    mq_regions = sum(1 for count in result.get_successful_results() if count > 0)

    if result.successful_regions > 0:
        summary.append({
            "service": "mq",
            "regions": mq_regions,
            "count": mq_total,
            "status": "OK" if mq_total > 0 else "EMPTY",
            "hint": "mq_enum" if mq_total > 0 else "no resources found",
        })
    else:
        first_error = result.results[0].error if result.results else None
        summary.append({
            "service": "mq",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(first_error) if first_error else "unknown error",
        })

    # ---------- IAM (global service - no parallelization needed) ----------
    iam_users = None
    iam_groups = None
    iam_policies = None

    try:
        iam = aws_sess.client("iam")

        # Users - with improved error handling
        try:
            users_count = 0
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                users_count += len(page.get("Users", []))
            iam_users = users_count
        except Exception as e:
            error = categorize_error(e)
            if error.category != ErrorCategory.AUTHORIZATION:
                # If it's not a permission issue, it might be more serious
                console.print(f"[yellow]IAM Users:[/yellow] {error.format_for_display()}")

        # Groups - with improved error handling
        try:
            groups_count = 0
            paginator = iam.get_paginator("list_groups")
            for page in paginator.paginate():
                groups_count += len(page.get("Groups", []))
            iam_groups = groups_count
        except Exception as e:
            error = categorize_error(e)
            if error.category != ErrorCategory.AUTHORIZATION:
                console.print(f"[yellow]IAM Groups:[/yellow] {error.format_for_display()}")

        # Policies - with improved error handling
        try:
            policies_count = 0
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="All"):
                policies_count += len(page.get("Policies", []))
            iam_policies = policies_count
        except Exception as e:
            error = categorize_error(e)
            if error.category != ErrorCategory.AUTHORIZATION:
                console.print(f"[yellow]IAM Policies:[/yellow] {error.format_for_display()}")

        # Build summary
        known_counts = [c for c in (iam_users, iam_groups, iam_policies) if c is not None]
        total_known = sum(known_counts) if known_counts else 0

        if known_counts:
            parts = []
            if iam_users is not None:
                parts.append(f"users={iam_users}")
            else:
                parts.append("users: no access")

            if iam_groups is not None:
                parts.append(f"groups={iam_groups}")
            else:
                parts.append("groups: no access")

            if iam_policies is not None:
                parts.append(f"policies={iam_policies}")
            else:
                parts.append("policies: no access")

            hint = ", ".join(parts)

            summary.append({
                "service": "iam",
                "regions": 1,  # IAM is global
                "count": total_known,
                "status": "OK" if total_known > 0 else "EMPTY",
                "hint": hint,
            })
        else:
            summary.append({
                "service": "iam",
                "regions": 0,
                "count": 0,
                "status": "ERROR",
                "hint": "no access to iam (users, groups, policies)",
            })

    except Exception as e:
        error = categorize_error(e)
        summary.append({
            "service": "iam",
            "regions": 0,
            "count": 0,
            "status": "ERROR",
            "hint": _format_error_hint(error),
        })

    # ---------- Print summary ----------
    table = Table(title="Quick Enumeration Summary")
    table.add_column("Service", style="cyan")
    table.add_column("Regions")
    table.add_column("Resources")
    table.add_column("Status")
    table.add_column("Next step")

    for row in summary:
        status = row.get("status", "UNKNOWN")
        if status == "OK":
            status_str = "[green]OK[/green]"
        elif status == "EMPTY":
            status_str = "[yellow]EMPTY[/yellow]"
        elif status == "ERROR":
            status_str = "[red]ERROR[/red]"
        else:
            status_str = status

        table.add_row(
            row["service"],
            str(row["regions"]),
            str(row["count"]),
            status_str,
            row["hint"],
        )

    console.print(table)
