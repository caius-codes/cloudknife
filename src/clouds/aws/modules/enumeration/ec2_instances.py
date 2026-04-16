import base64
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions
from src.clouds.aws.utils.parallel import RegionalExecutor
from src.clouds.aws.utils.error_handling import with_retry, RetryConfig


console = Console()


def _get_instance_name(tags: List[Dict[str, Any]] | None) -> str:
    if not tags:
        return ""
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def _get_tag_value(tags: List[Dict[str, Any]] | None, key: str) -> str:
    """Extract a specific tag value from instance tags (case-insensitive)."""
    if not tags:
        return ""
    for t in tags:
        if t.get("Key", "").lower() == key.lower():
            return t.get("Value", "")
    return ""


def _get_all_tags(tags: List[Dict[str, Any]] | None) -> Dict[str, str]:
    """Convert tag list to dictionary."""
    if not tags:
        return {}
    return {tag.get("Key", ""): tag.get("Value", "") for tag in tags}


def enumerate_ec2(session_mgr: AWSSessionManager) -> None:
    """
    Comprehensive EC2 instance enumeration with security-focused analysis.

    Collects:
    - Basic metadata (ID, name, state, type, platform, architecture, launch time)
    - Networking (VPC, subnet, IPs, DNS, security groups, source/dest check)
    - Security (IAM instance profile, SSH key, IMDS configuration)
    - UserData content (requires ec2:DescribeInstanceAttribute)
    - Tags (including Description, Environment, Owner if present)
    - Additional metadata (AMI ID, monitoring, CPU, EBS optimization)

    Security Analysis:
    - Identifies IMDSv1 instances (vulnerable to SSRF credential theft)
    - Highlights instances with IAM roles (privilege escalation vectors)
    - Detects publicly accessible instances
    - Flags instances with UserData (potential secrets)

    Multi-region aware with parallel execution and automatic retry on failures.
    Saves comprehensive results under 'ec2_instances' in session data.

    Required Permissions:
    - ec2:DescribeInstances (required)
    - ec2:DescribeInstanceAttribute (for UserData)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="EC2")
    console.print(
        f"[bold blue]🔍 Enumerating EC2 instances and userData across {len(regions)} regions[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()

    def enumerate_ec2_region(region: str) -> List[Dict[str, Any]]:
        """
        Enumerate EC2 instances in a single region.
        This function will be executed in parallel for each region.
        """
        region_instances: List[Dict[str, Any]] = []
        ec2_client = aws_sess.client("ec2", region_name=region)

        # Use retry decorator for describe_instances pagination
        @with_retry(RetryConfig(max_attempts=3, base_delay=2.0), silent=True)
        def get_instances_page():
            paginator = ec2_client.get_paginator("describe_instances")
            return list(paginator.paginate())

        pages = get_instances_page()

        for page in pages:
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    instance_id = inst["InstanceId"]
                    tags = inst.get("Tags", [])
                    name = _get_instance_name(tags)
                    all_tags = _get_all_tags(tags)

                    # Basic instance info
                    state = inst.get("State", {}).get("Name", "")
                    instance_type = inst.get("InstanceType", "")
                    platform = inst.get("Platform", "Linux")  # "windows" if Windows, else Linux
                    architecture = inst.get("Architecture", "")

                    # Placement & networking
                    az = inst.get("Placement", {}).get("AvailabilityZone", "")
                    tenancy = inst.get("Placement", {}).get("Tenancy", "default")
                    vpc_id = inst.get("VpcId", "")
                    subnet_id = inst.get("SubnetId", "")
                    private_ip = inst.get("PrivateIpAddress", "")
                    public_ip = inst.get("PublicIpAddress", "")
                    public_dns = inst.get("PublicDnsName", "")
                    source_dest_check = inst.get("SourceDestCheck", True)

                    # Security
                    sgs = [
                        f"{sg.get('GroupName','')} ({sg.get('GroupId','')})"
                        for sg in inst.get("SecurityGroups", [])
                    ]
                    key_name = inst.get("KeyName", "")

                    # IAM Instance Profile (critical for privilege escalation!)
                    iam_profile = inst.get("IamInstanceProfile", {})
                    iam_instance_profile_arn = iam_profile.get("Arn", "")

                    # IMDS configuration (IMDSv1 = vulnerable to SSRF!)
                    metadata_options = inst.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")
                    imds_version = "v2" if http_tokens == "required" else "v1"
                    imds_endpoint = metadata_options.get("HttpEndpoint", "enabled")

                    # Additional metadata
                    launch_time = str(inst.get("LaunchTime", ""))[:19]
                    image_id = inst.get("ImageId", "")
                    root_device_type = inst.get("RootDeviceType", "")
                    ebs_optimized = inst.get("EbsOptimized", False)
                    monitoring_state = inst.get("Monitoring", {}).get("State", "disabled")

                    # CPU options
                    cpu_opts = inst.get("CpuOptions", {})
                    core_count = cpu_opts.get("CoreCount", 0)
                    threads_per_core = cpu_opts.get("ThreadsPerCore", 0)

                    # Custom tags (description, environment, owner)
                    description = _get_tag_value(tags, "Description")
                    environment = _get_tag_value(tags, "Environment")
                    owner = _get_tag_value(tags, "Owner")

                    # UserData retrieval with retry
                    user_data_decoded = ""
                    user_data_present = False

                    @with_retry(RetryConfig(max_attempts=2, base_delay=1.0), silent=True)
                    def get_user_data():
                        return ec2_client.describe_instance_attribute(
                            InstanceId=instance_id,
                            Attribute="userData",
                        )

                    try:
                        ud_resp = get_user_data()
                        ud = ud_resp.get("UserData", {})
                        if ud and "Value" in ud and ud["Value"]:
                            user_data_decoded = base64.b64decode(ud["Value"]).decode(
                                "utf-8", errors="replace"
                            )
                            user_data_present = True
                    except Exception as e:
                        user_data_decoded = f"[ERROR retrieving userData: {str(e)[:80]}]"

                    region_instances.append({
                        # Basic info
                        "Region": region,
                        "InstanceId": instance_id,
                        "Name": name,
                        "State": state,
                        "InstanceType": instance_type,
                        "Platform": platform,
                        "Architecture": architecture,
                        "LaunchTime": launch_time,
                        "ImageId": image_id,

                        # Networking
                        "AZ": az,
                        "Tenancy": tenancy,
                        "VpcId": vpc_id,
                        "SubnetId": subnet_id,
                        "PrivateIp": private_ip,
                        "PublicIp": public_ip,
                        "PublicDnsName": public_dns,
                        "SourceDestCheck": source_dest_check,

                        # Security
                        "SecurityGroups": sgs,
                        "KeyName": key_name,
                        "IamInstanceProfile": iam_instance_profile_arn,

                        # IMDS configuration (CRITICAL for SSRF attacks)
                        "ImdsVersion": imds_version,
                        "ImdsEndpoint": imds_endpoint,
                        "HttpTokens": http_tokens,

                        # UserData
                        "UserData": user_data_decoded,
                        "HasUserData": user_data_present,

                        # Additional metadata
                        "RootDeviceType": root_device_type,
                        "EbsOptimized": ebs_optimized,
                        "Monitoring": monitoring_state,
                        "CoreCount": core_count,
                        "ThreadsPerCore": threads_per_core,

                        # Tags
                        "Tags": all_tags,
                        "Description": description,
                        "Environment": environment,
                        "Owner": owner,
                    })

        return region_instances

    # Execute in parallel across all regions
    executor = RegionalExecutor(
        max_workers=min(len(regions), 8),
        show_progress=True
    )

    result = executor.execute(
        regions=regions,
        operation=enumerate_ec2_region,
        operation_name="EC2 Instances + UserData"
    )

    # Aggregate all instances from successful regions
    all_instances = result.get_all_items()

    # Show summary if there were failures
    if result.failed_regions > 0:
        console.print(
            f"\n[yellow]Warning: Failed to enumerate {result.failed_regions} region(s)[/yellow]"
        )
        for failed_region in result.get_failed_regions():
            console.print(f"  • {failed_region}")

    # Save in session
    session_mgr.save_enumeration_data("ec2_instances", all_instances)

    if not all_instances:
        console.print("[yellow]No EC2 instances found in the selected regions.[/yellow]")
        return

    # Summary table with security-focused columns
    table = Table(title=f"EC2 Instances (total: {len(all_instances)})")
    table.add_column("Region", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("InstanceId", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Name", overflow="fold", no_wrap=False)
    table.add_column("State", overflow="fold", no_wrap=False)
    table.add_column("Platform", overflow="fold", no_wrap=False)
    table.add_column("AZ", overflow="fold", no_wrap=False)
    table.add_column("Private IP", overflow="fold", no_wrap=False)
    table.add_column("Public IP", overflow="fold", no_wrap=False)
    table.add_column("IAM Role", style="bold", overflow="fold", no_wrap=False)
    table.add_column("IMDS", style="bold", overflow="fold", no_wrap=False)
    table.add_column("KeyName", overflow="fold", no_wrap=False)
    table.add_column("UserData", overflow="fold", no_wrap=False)

    # Track security issues
    imdsv1_instances = []
    iam_role_instances = []
    public_instances = []

    for inst in all_instances:
        # UserData flag
        ud_flag = "📜" if inst["HasUserData"] else "–"

        # IAM Role indicator (green checkmark if present - privilege escalation vector!)
        has_iam_role = bool(inst.get("IamInstanceProfile"))
        if has_iam_role:
            iam_display = "[green bold]✓ Role[/green bold]"
            iam_role_instances.append(inst)
        else:
            iam_display = "–"

        # IMDS version indicator (v1 = vulnerable to SSRF attacks!)
        imds_version = inst.get("ImdsVersion", "unknown")
        if imds_version == "v1":
            imds_display = "[red bold]v1 ⚠️[/red bold]"
            imdsv1_instances.append(inst)
        elif imds_version == "v2":
            imds_display = "[green]v2[/green]"
        else:
            imds_display = "[dim]unknown[/dim]"

        # Platform shorthand
        platform = inst.get("Platform", "Linux")
        platform_display = "Win" if platform.lower() == "windows" else "Linux"

        # Public IP tracking
        public_ip = inst.get("PublicIp", "")
        if public_ip:
            public_instances.append(inst)

        table.add_row(
            inst["Region"],
            inst["InstanceId"],
            inst["Name"][:30] if inst.get("Name") else "–",  # Truncate long names
            inst["State"],
            platform_display,
            inst.get("AZ", "–"),
            inst.get("PrivateIp", "–"),
            public_ip if public_ip else "–",
            iam_display,
            imds_display,
            inst.get("KeyName", "–"),
            ud_flag,
        )

    console.print(table)

    # Security warnings and actionable intelligence
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if imdsv1_instances:
        console.print(
            f"\n[red bold]🚨 IMDSv1 Vulnerability:[/red bold] {len(imdsv1_instances)} instance(s) use IMDSv1"
        )
        console.print("[yellow]IMDSv1 is vulnerable to SSRF attacks for credential theft.[/yellow]")
        console.print("[dim]If you can trigger an HTTP request from the instance, you can steal IAM credentials:[/dim]")
        console.print("[dim]  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/[/dim]")
        for inst in imdsv1_instances[:5]:  # Show first 5
            console.print(f"  • {inst['InstanceId']} ({inst['Name']}) in {inst['Region']}")
        if len(imdsv1_instances) > 5:
            console.print(f"  [dim]... and {len(imdsv1_instances) - 5} more[/dim]")

    if iam_role_instances:
        console.print(
            f"\n[green bold]🎯 Privilege Escalation Vector:[/green bold] {len(iam_role_instances)} instance(s) with IAM roles"
        )
        console.print("[yellow]RCE on these instances = automatic role assumption[/yellow]")
        console.print("[dim]Use 'ssm_rce' or 'ec2_startup_shell' to exploit if you have the right permissions.[/dim]")
        for inst in iam_role_instances[:5]:
            role_name = inst['IamInstanceProfile'].split('/')[-1] if inst.get('IamInstanceProfile') else 'unknown'
            console.print(
                f"  • {inst['InstanceId']} ({inst['Name']}) → [cyan]{role_name}[/cyan] in {inst['Region']}"
            )
        if len(iam_role_instances) > 5:
            console.print(f"  [dim]... and {len(iam_role_instances) - 5} more[/dim]")

    if public_instances:
        console.print(
            f"\n[cyan]🌐 Public Exposure:[/cyan] {len(public_instances)} instance(s) with public IPs"
        )
        console.print("[dim]These instances are directly accessible from the internet (check security groups).[/dim]")

    # UserData warning
    instances_with_userdata = [inst for inst in all_instances if inst.get("HasUserData")]
    if instances_with_userdata:
        console.print(
            f"\n[yellow]📜 UserData Found:[/yellow] {len(instances_with_userdata)} instance(s) have userData"
        )
        console.print("[dim]UserData often contains secrets (credentials, tokens, API keys, scripts).[/dim]")
        console.print("[dim]Use 'show_ec2_userdata <InstanceId>' to inspect content.[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ EC2 enumeration complete. {len(all_instances)} instances stored under 'ec2_instances' in session.[/green]"
    )
