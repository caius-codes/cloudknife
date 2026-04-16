"""
RDS Instance Enumeration Module

Enumerates RDS instances and Aurora clusters across configured regions.
Collects security-relevant information including:
- Endpoint and port (for connection attempts)
- Public accessibility
- Encryption status
- IAM authentication (enables passwordless access via tokens)
- Engine version (for CVE research)
- VPC/Security Group configuration
"""

from typing import List, Dict, Any

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_rds_instances(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate RDS instances and Aurora clusters across configured regions.
    Stores results under 'rds_instances' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="RDS")
    console.print(
        f"[bold blue]🔍 Enumerating RDS instances and clusters in regions: {', '.join(regions)}[/bold blue]"
    )

    client_factory = RegionalClientFactory(session_mgr)
    all_instances: List[Dict[str, Any]] = []
    all_clusters: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            rds = client_factory.get_client("rds", region)

            # Enumerate RDS instances
            try:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        instance_data = _extract_instance_data(db, region)
                        all_instances.append(instance_data)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    console.print(f"[yellow]  Access denied for DescribeDBInstances in {region}[/yellow]")
                else:
                    console.print(f"[red]  Error listing RDS instances: {code}[/red]")

            # Enumerate Aurora clusters
            try:
                paginator = rds.get_paginator("describe_db_clusters")
                for page in paginator.paginate():
                    for cluster in page.get("DBClusters", []):
                        cluster_data = _extract_cluster_data(cluster, region)
                        all_clusters.append(cluster_data)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    console.print(f"[yellow]  Access denied for DescribeDBClusters in {region}[/yellow]")
                else:
                    console.print(f"[red]  Error listing Aurora clusters: {code}[/red]")

            instance_count = len([i for i in all_instances if i["Region"] == region])
            cluster_count = len([c for c in all_clusters if c["Region"] == region])
            console.print(f"[green]  Found {instance_count} instances, {cluster_count} clusters[/green]")

        except Exception as e:
            console.print(f"[red]RDS enumeration failed in region {region}: {str(e)}[/red]")

    # Save results
    session_mgr.save_enumeration_data("rds_instances", all_instances)
    session_mgr.save_enumeration_data("rds_clusters", all_clusters)

    # Display instances table
    if all_instances:
        _display_instances_table(all_instances)
    else:
        console.print("[yellow]No RDS instances found.[/yellow]")

    # Display clusters table
    if all_clusters:
        _display_clusters_table(all_clusters)

    # Security summary
    _display_security_summary(all_instances, all_clusters)

    console.print(
        "[green]RDS data stored under keys 'rds_instances' and 'rds_clusters' in session data.[/green]"
    )


def _extract_instance_data(db: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Extract relevant fields from a DBInstance response."""
    endpoint = db.get("Endpoint", {})
    vpc_sgs = [sg.get("VpcSecurityGroupId", "") for sg in db.get("VpcSecurityGroups", [])]

    return {
        "Region": region,
        "DBInstanceIdentifier": db.get("DBInstanceIdentifier", ""),
        "DBInstanceClass": db.get("DBInstanceClass", ""),
        "Engine": db.get("Engine", ""),
        "EngineVersion": db.get("EngineVersion", ""),
        "DBInstanceStatus": db.get("DBInstanceStatus", ""),
        "Endpoint": endpoint.get("Address", ""),
        "Port": endpoint.get("Port", ""),
        "MasterUsername": db.get("MasterUsername", ""),
        "DBName": db.get("DBName", ""),
        "PubliclyAccessible": db.get("PubliclyAccessible", False),
        "StorageEncrypted": db.get("StorageEncrypted", False),
        "KmsKeyId": db.get("KmsKeyId", ""),
        "IAMDatabaseAuthenticationEnabled": db.get("IAMDatabaseAuthenticationEnabled", False),
        "DeletionProtection": db.get("DeletionProtection", False),
        "MultiAZ": db.get("MultiAZ", False),
        "VpcId": db.get("DBSubnetGroup", {}).get("VpcId", ""),
        "DBSubnetGroupName": db.get("DBSubnetGroup", {}).get("DBSubnetGroupName", ""),
        "VpcSecurityGroups": vpc_sgs,
        "AvailabilityZone": db.get("AvailabilityZone", ""),
        "AllocatedStorage": db.get("AllocatedStorage", 0),
        "DBClusterIdentifier": db.get("DBClusterIdentifier", ""),  # If part of Aurora
        "ReadReplicaSourceDBInstanceIdentifier": db.get("ReadReplicaSourceDBInstanceIdentifier", ""),
        "ReadReplicaDBInstanceIdentifiers": db.get("ReadReplicaDBInstanceIdentifiers", []),
    }


def _extract_cluster_data(cluster: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Extract relevant fields from a DBCluster response."""
    vpc_sgs = [sg.get("VpcSecurityGroupId", "") for sg in cluster.get("VpcSecurityGroups", [])]

    return {
        "Region": region,
        "DBClusterIdentifier": cluster.get("DBClusterIdentifier", ""),
        "Engine": cluster.get("Engine", ""),
        "EngineVersion": cluster.get("EngineVersion", ""),
        "EngineMode": cluster.get("EngineMode", ""),  # provisioned, serverless, etc.
        "Status": cluster.get("Status", ""),
        "Endpoint": cluster.get("Endpoint", ""),
        "ReaderEndpoint": cluster.get("ReaderEndpoint", ""),
        "Port": cluster.get("Port", ""),
        "MasterUsername": cluster.get("MasterUsername", ""),
        "DatabaseName": cluster.get("DatabaseName", ""),
        "StorageEncrypted": cluster.get("StorageEncrypted", False),
        "KmsKeyId": cluster.get("KmsKeyId", ""),
        "IAMDatabaseAuthenticationEnabled": cluster.get("IAMDatabaseAuthenticationEnabled", False),
        "DeletionProtection": cluster.get("DeletionProtection", False),
        "MultiAZ": cluster.get("MultiAZ", False),
        "VpcSecurityGroups": vpc_sgs,
        "DBClusterMembers": [
            {
                "DBInstanceIdentifier": m.get("DBInstanceIdentifier", ""),
                "IsClusterWriter": m.get("IsClusterWriter", False),
            }
            for m in cluster.get("DBClusterMembers", [])
        ],
        "BackupRetentionPeriod": cluster.get("BackupRetentionPeriod", 0),
        "PubliclyAccessible": cluster.get("PubliclyAccessible", False),
    }


def _display_instances_table(instances: List[Dict[str, Any]]) -> None:
    """Display RDS instances in a formatted table."""
    table = Table(title=f"RDS Instances (total: {len(instances)})")
    table.add_column("Region", style="magenta")
    table.add_column("Identifier", style="cyan")
    table.add_column("Engine")
    table.add_column("Status")
    table.add_column("Endpoint")
    table.add_column("Public")
    table.add_column("Encrypted")
    table.add_column("IAM Auth")

    for inst in instances[:100]:  # Limit display
        public_flag = "[red]YES[/red]" if inst["PubliclyAccessible"] else "[green]No[/green]"
        enc_flag = "[green]Yes[/green]" if inst["StorageEncrypted"] else "[red]NO[/red]"
        iam_flag = "[yellow]YES[/yellow]" if inst["IAMDatabaseAuthenticationEnabled"] else "No"

        table.add_row(
            inst["Region"],
            inst["DBInstanceIdentifier"],
            f"{inst['Engine']} {inst['EngineVersion']}",
            inst["DBInstanceStatus"],
            f"{inst['Endpoint']}:{inst['Port']}" if inst["Endpoint"] else "-",
            public_flag,
            enc_flag,
            iam_flag,
        )

    console.print(table)


def _display_clusters_table(clusters: List[Dict[str, Any]]) -> None:
    """Display Aurora clusters in a formatted table."""
    table = Table(title=f"Aurora Clusters (total: {len(clusters)})")
    table.add_column("Region", style="magenta")
    table.add_column("Identifier", style="cyan")
    table.add_column("Engine")
    table.add_column("Mode")
    table.add_column("Endpoint")
    table.add_column("Encrypted")
    table.add_column("IAM Auth")
    table.add_column("Members")

    for cluster in clusters[:50]:  # Limit display
        enc_flag = "[green]Yes[/green]" if cluster["StorageEncrypted"] else "[red]NO[/red]"
        iam_flag = "[yellow]YES[/yellow]" if cluster["IAMDatabaseAuthenticationEnabled"] else "No"
        members = len(cluster.get("DBClusterMembers", []))

        table.add_row(
            cluster["Region"],
            cluster["DBClusterIdentifier"],
            f"{cluster['Engine']} {cluster['EngineVersion']}",
            cluster.get("EngineMode", "provisioned"),
            f"{cluster['Endpoint']}:{cluster['Port']}" if cluster["Endpoint"] else "-",
            enc_flag,
            iam_flag,
            str(members),
        )

    console.print(table)


def _display_security_summary(instances: List[Dict[str, Any]], clusters: List[Dict[str, Any]]) -> None:
    """Display security-relevant summary."""
    total = len(instances) + len(clusters)
    if total == 0:
        return

    public_instances = [i for i in instances if i.get("PubliclyAccessible")]
    unencrypted_instances = [i for i in instances if not i.get("StorageEncrypted")]
    iam_auth_instances = [i for i in instances if i.get("IAMDatabaseAuthenticationEnabled")]

    unencrypted_clusters = [c for c in clusters if not c.get("StorageEncrypted")]
    iam_auth_clusters = [c for c in clusters if c.get("IAMDatabaseAuthenticationEnabled")]

    console.print("\n[bold]Security Summary:[/bold]")

    if public_instances:
        console.print(
            f"[bold red]  ⚠ {len(public_instances)} publicly accessible instance(s)[/bold red]"
        )
        for inst in public_instances[:5]:
            console.print(f"    - {inst['DBInstanceIdentifier']} ({inst['Endpoint']})")

    if unencrypted_instances or unencrypted_clusters:
        total_unenc = len(unencrypted_instances) + len(unencrypted_clusters)
        console.print(f"[bold red]  ⚠ {total_unenc} unencrypted database(s)[/bold red]")

    if iam_auth_instances or iam_auth_clusters:
        total_iam = len(iam_auth_instances) + len(iam_auth_clusters)
        console.print(
            f"[bold yellow]  🔑 {total_iam} database(s) with IAM authentication enabled[/bold yellow]"
        )
        console.print("    [dim]Use 'rds_iam_token' to generate access tokens[/dim]")
