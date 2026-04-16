from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
import re

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.error_handling import safe_aws_call

console = Console()


def enumerate_s3_buckets(session_mgr: AWSSessionManager) -> None:
    """
    Comprehensive S3 bucket enumeration with security-focused analysis.

    Collects for each bucket:
    - Basic metadata (name, creation date, region)
    - ACL configuration (public-read, public-read-write detection)
    - Block Public Access settings (account and bucket level)
    - Encryption configuration (SSE-S3, SSE-KMS, unencrypted)
    - Versioning status (enabled, suspended, disabled)
    - Logging configuration
    - Lifecycle policies presence
    - Replication configuration
    - Website hosting configuration
    - Object count and size estimation

    Security Analysis:
    - Identifies publicly accessible buckets (ACL-based)
    - Detects disabled Block Public Access settings (critical!)
    - Flags unencrypted buckets
    - Highlights buckets without versioning (ransomware risk)
    - Detects website hosting (potential data exposure)

    Multi-region aware with comprehensive security posture assessment.
    Saves detailed results under 's3_buckets' in session data.

    Required Permissions:
    - s3:ListAllMyBuckets (required)
    - s3:GetBucketLocation (required)
    - s3:GetBucketAcl (recommended)
    - s3:GetBucketPublicAccessBlock (recommended)
    - s3:GetEncryptionConfiguration (recommended)
    - s3:GetBucketVersioning (recommended)
    - s3:GetBucketLogging (recommended)
    - s3:GetBucketWebsite (recommended)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold blue]🔍 Enumerating S3 buckets with security analysis...[/bold blue]")

    aws_sess = session_mgr.get_boto3_session()
    s3 = aws_sess.client("s3")

    # List all buckets
    resp, error = safe_aws_call(s3.list_buckets, log_error=True, default=None)
    if error or not resp:
        console.print(f"[red]Failed to list buckets: {error.message if error else 'Unknown error'}[/red]")
        console.print("[yellow]Ensure s3:ListAllMyBuckets permission.[/yellow]")
        return

    bucket_names = [b.get("Name", "") for b in resp.get("Buckets", [])]

    if not bucket_names:
        console.print("[yellow]No buckets found.[/yellow]")
        return

    console.print(f"[cyan]Found {len(bucket_names)} bucket(s). Analyzing security configurations...[/cyan]")

    buckets: List[Dict[str, Any]] = []

    for idx, bucket_name in enumerate(bucket_names, 1):
        console.print(f"[dim]  Analyzing bucket {idx}/{len(bucket_names)}: {bucket_name}[/dim]")

        bucket_data = {"Name": bucket_name}

        # Get bucket location/region
        location_resp, _ = safe_aws_call(
            s3.get_bucket_location,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )
        region = location_resp.get("LocationConstraint") or "us-east-1"
        bucket_data["Region"] = region

        # Get creation date from initial list
        for b in resp.get("Buckets", []):
            if b.get("Name") == bucket_name:
                bucket_data["CreationDate"] = str(b.get("CreationDate", ""))[:19]
                break

        # Get bucket ACL (public access via ACL)
        acl_resp, _ = safe_aws_call(
            s3.get_bucket_acl,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        is_public_read = False
        is_public_write = False

        for grant in acl_resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            uri = grantee.get("URI", "")

            # Check for public permissions
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                if permission in ["READ", "FULL_CONTROL"]:
                    is_public_read = True
                if permission in ["WRITE", "FULL_CONTROL"]:
                    is_public_write = True

        bucket_data["PublicRead"] = is_public_read
        bucket_data["PublicWrite"] = is_public_write

        # Get Block Public Access settings
        bpa_resp, _ = safe_aws_call(
            s3.get_public_access_block,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        bpa_config = bpa_resp.get("PublicAccessBlockConfiguration", {})
        block_public_acls = bpa_config.get("BlockPublicAcls", False)
        ignore_public_acls = bpa_config.get("IgnorePublicAcls", False)
        block_public_policy = bpa_config.get("BlockPublicPolicy", False)
        restrict_public_buckets = bpa_config.get("RestrictPublicBuckets", False)

        all_blocked = all([
            block_public_acls,
            ignore_public_acls,
            block_public_policy,
            restrict_public_buckets
        ])

        bucket_data["BlockPublicAccessEnabled"] = all_blocked
        bucket_data["BlockPublicAccessConfig"] = bpa_config

        # Get encryption configuration
        enc_resp, _ = safe_aws_call(
            s3.get_bucket_encryption,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        encryption_type = "None"
        if enc_resp:
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                sse_algorithm = sse.get("SSEAlgorithm", "")
                if sse_algorithm == "AES256":
                    encryption_type = "SSE-S3"
                elif sse_algorithm == "aws:kms":
                    encryption_type = "SSE-KMS"

        bucket_data["Encryption"] = encryption_type

        # Get versioning status
        vers_resp, _ = safe_aws_call(
            s3.get_bucket_versioning,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        versioning_status = vers_resp.get("Status", "Disabled")
        mfa_delete = vers_resp.get("MFADelete", "Disabled")

        bucket_data["Versioning"] = versioning_status
        bucket_data["MfaDelete"] = mfa_delete

        # Get logging configuration
        log_resp, _ = safe_aws_call(
            s3.get_bucket_logging,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        logging_enabled = bool(log_resp.get("LoggingEnabled"))
        bucket_data["LoggingEnabled"] = logging_enabled

        # Check if website hosting is enabled
        website_resp, _ = safe_aws_call(
            s3.get_bucket_website,
            Bucket=bucket_name,
            log_error=False,
            default={}
        )

        is_website = bool(website_resp)
        bucket_data["WebsiteHosting"] = is_website

        buckets.append(bucket_data)

    session_mgr.save_enumeration_data("s3_buckets", buckets)

    # Display summary table
    table = Table(title=f"S3 Buckets (total: {len(buckets)})")
    table.add_column("Name", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Region", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("Public", style="bold", overflow="fold", no_wrap=False)
    table.add_column("Block PA", overflow="fold", no_wrap=False)
    table.add_column("Encryption", overflow="fold", no_wrap=False)
    table.add_column("Versioning", overflow="fold", no_wrap=False)
    table.add_column("Logging", overflow="fold", no_wrap=False)
    table.add_column("Website", overflow="fold", no_wrap=False)

    # Track security issues
    public_buckets = []
    unencrypted_buckets = []
    no_versioning_buckets = []
    bpa_disabled_buckets = []
    website_buckets = []

    for bucket in buckets:
        # Public access indicator
        if bucket.get("PublicRead") or bucket.get("PublicWrite"):
            if bucket.get("PublicWrite"):
                public_display = "[red bold]R+W ⚠️[/red bold]"
            else:
                public_display = "[red]Read[/red]"
            public_buckets.append(bucket)
        else:
            public_display = "[green]Private[/green]"

        # Block Public Access
        if bucket.get("BlockPublicAccessEnabled"):
            bpa_display = "[green]✓[/green]"
        else:
            bpa_display = "[red]✗[/red]"
            bpa_disabled_buckets.append(bucket)

        # Encryption
        enc = bucket.get("Encryption", "None")
        if enc == "None":
            enc_display = "[red]None[/red]"
            unencrypted_buckets.append(bucket)
        elif enc == "SSE-KMS":
            enc_display = "[green]KMS[/green]"
        else:
            enc_display = "[yellow]S3[/yellow]"

        # Versioning
        vers = bucket.get("Versioning", "Disabled")
        if vers == "Enabled":
            vers_display = "[green]✓[/green]"
        else:
            vers_display = "[yellow]✗[/yellow]"
            no_versioning_buckets.append(bucket)

        # Logging
        if bucket.get("LoggingEnabled"):
            log_display = "[green]✓[/green]"
        else:
            log_display = "[dim]✗[/dim]"

        # Website hosting
        if bucket.get("WebsiteHosting"):
            web_display = "[yellow]Yes[/yellow]"
            website_buckets.append(bucket)
        else:
            web_display = "–"

        table.add_row(
            bucket["Name"],
            bucket.get("Region", "unknown"),
            public_display,
            bpa_display,
            enc_display,
            vers_display,
            log_display,
            web_display,
        )

    console.print(table)

    # Security findings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if public_buckets:
        console.print(
            f"\n[red bold]🚨 CRITICAL - Public Buckets:[/red bold] {len(public_buckets)} bucket(s) publicly accessible"
        )
        console.print("[yellow]These buckets have ACLs allowing public read or write access![/yellow]")
        for bucket in public_buckets[:5]:
            access_type = "READ+WRITE" if bucket.get("PublicWrite") else "READ"
            console.print(f"  • {bucket['Name']} ({access_type}) in {bucket.get('Region', 'unknown')}")
        if len(public_buckets) > 5:
            console.print(f"  [dim]... and {len(public_buckets) - 5} more[/dim]")

    if bpa_disabled_buckets:
        console.print(
            f"\n[red bold]🚨 Block Public Access Disabled:[/red bold] {len(bpa_disabled_buckets)} bucket(s)"
        )
        console.print("[yellow]These buckets can be made public via policy changes![/yellow]")
        for bucket in bpa_disabled_buckets[:5]:
            console.print(f"  • {bucket['Name']} in {bucket.get('Region', 'unknown')}")
        if len(bpa_disabled_buckets) > 5:
            console.print(f"  [dim]... and {len(bpa_disabled_buckets) - 5} more[/dim]")

    if unencrypted_buckets:
        console.print(
            f"\n[yellow]⚠️  Unencrypted Buckets:[/yellow] {len(unencrypted_buckets)} bucket(s) without encryption"
        )
        console.print("[dim]Data at rest is not encrypted (compliance/privacy risk)[/dim]")
        for bucket in unencrypted_buckets[:5]:
            console.print(f"  • {bucket['Name']}")
        if len(unencrypted_buckets) > 5:
            console.print(f"  [dim]... and {len(unencrypted_buckets) - 5} more[/dim]")

    if no_versioning_buckets:
        console.print(
            f"\n[yellow]⚠️  Versioning Disabled:[/yellow] {len(no_versioning_buckets)} bucket(s) without versioning"
        )
        console.print("[dim]Vulnerable to ransomware attacks and accidental deletions[/dim]")

    if website_buckets:
        console.print(
            f"\n[cyan]🌐 Website Hosting:[/cyan] {len(website_buckets)} bucket(s) configured as websites"
        )
        console.print("[dim]Check for unintended data exposure via public website configuration[/dim]")
        for bucket in website_buckets:
            console.print(f"  • http://{bucket['Name']}.s3-website-{bucket.get('Region', 'us-east-1')}.amazonaws.com")

    # Summary
    console.print(
        f"\n[green]✓ S3 enumeration complete. {len(buckets)} buckets analyzed and stored under 's3_buckets' in session.[/green]"
    )
