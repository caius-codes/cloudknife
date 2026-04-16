"""
EC2 Windows Password Retrieval Module

Retrieves and decrypts the Administrator password for Windows EC2 instances.
Requires the private key (.pem) used when launching the instance.

Useful for:
- Post-exploitation when private keys are found in S3, Lambda, Secrets, etc.
- Lateral movement to Windows instances in the environment
- Red team operations requiring RDP access
"""

import base64
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from ...aws_session import AWSSessionManager

console = Console()


def _decrypt_password(encrypted_password_b64: str, private_key_path: str) -> Optional[str]:
    """
    Decrypt the RSA-encrypted password using the private key.

    Args:
        encrypted_password_b64: Base64-encoded encrypted password from AWS
        private_key_path: Path to the PEM private key file

    Returns:
        Decrypted password string, or None if decryption fails
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        console.print("[red]Error: 'cryptography' library is required for password decryption.[/red]")
        console.print("[dim]Install with: pip install cryptography[/dim]")
        return None

    try:
        # Read private key
        key_path = Path(private_key_path).expanduser().resolve()
        if not key_path.exists():
            console.print(f"[red]Private key file not found: {key_path}[/red]")
            return None

        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Assumes unencrypted key
                backend=default_backend()
            )

        # Decode base64 encrypted password
        encrypted_password = base64.b64decode(encrypted_password_b64)

        # Decrypt using RSA PKCS1v15
        decrypted = private_key.decrypt(
            encrypted_password,
            padding.PKCS1v15()
        )

        return decrypted.decode("utf-8")

    except Exception as e:
        console.print(f"[red]Failed to decrypt password: {str(e)}[/red]")
        return None


def ec2_get_password(
    session_mgr: AWSSessionManager,
    instance_id: Optional[str] = None,
    private_key_path: Optional[str] = None,
    region: Optional[str] = None
):
    """
    Retrieve and decrypt the Administrator password for a Windows EC2 instance.

    Args:
        session_mgr: Session manager instance
        instance_id: EC2 instance ID
        private_key_path: Path to the private key (.pem) used to launch the instance
        region: AWS region (uses default if not specified)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print(Panel(
        "[bold blue]EC2 Windows Password Retrieval[/bold blue]\n\n"
        "Retrieves and decrypts the Administrator password for Windows EC2 instances.\n"
        "Requires the private key (.pem) that was used to launch the instance.\n\n"
        "[dim]Note: Password data is only available for instances launched with a key pair.[/dim]",
        border_style="blue"
    ))

    # Get instance ID
    if not instance_id:
        # Try to load from enumerated EC2 instances
        ec2_cache = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("ec2_instances", [])
        windows_instances = [i for i in ec2_cache if i.get("Platform", "").lower() == "windows"]

        if windows_instances:
            console.print(f"\n[dim]Found {len(windows_instances)} Windows instance(s) in cache:[/dim]")
            for idx, inst in enumerate(windows_instances[:10], 1):
                console.print(f"  [{idx}] {inst['InstanceId']} - {inst.get('Name', 'N/A')} ({inst.get('State', 'unknown')})")

        instance_id = Prompt.ask("[cyan]Instance ID[/cyan]")

    # Get region
    if not region:
        region = session_mgr.default_region
        # Try to infer from cache
        ec2_cache = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("ec2_instances", [])
        for inst in ec2_cache:
            if inst.get("InstanceId") == instance_id:
                # Extract region from AZ
                az = inst.get("AvailabilityZone", "")
                if az:
                    region = az[:-1]  # Remove AZ letter (e.g., us-east-1a -> us-east-1)
                break

    # Get private key path
    if not private_key_path:
        private_key_path = Prompt.ask("[cyan]Path to private key (.pem)[/cyan]")

    # Validate key path exists
    key_path = Path(private_key_path).expanduser().resolve()
    if not key_path.exists():
        console.print(f"[red]Private key file not found: {key_path}[/red]")
        return

    console.print(f"\n[bold blue]🔐 Retrieving password data for instance {instance_id}...[/bold blue]")
    console.print(f"[dim]Region: {region}[/dim]")
    console.print(f"[dim]Key: {key_path}[/dim]\n")

    # Create EC2 client for the specified region
    from boto3 import Session as Boto3Session

    base_sess = session_mgr.get_boto3_session()
    creds = base_sess.get_credentials()

    regional_sess = Boto3Session(
        aws_access_key_id=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_session_token=creds.token,
        region_name=region,
    )
    ec2 = regional_sess.client("ec2")

    try:
        # Get password data
        response = ec2.get_password_data(InstanceId=instance_id)

        password_data = response.get("PasswordData", "")
        timestamp = response.get("Timestamp", "")

        if not password_data:
            console.print("[yellow]No password data available for this instance.[/yellow]")
            console.print("[dim]Possible reasons:[/dim]")
            console.print("  • Instance was not launched with a key pair")
            console.print("  • Instance is not a Windows instance")
            console.print("  • Password has not been generated yet (wait ~4 minutes after launch)")
            console.print("  • Password was already retrieved and instance was stopped/started")
            return

        console.print("[green]✓ Password data retrieved successfully![/green]\n")

        # Decrypt the password
        console.print("[dim]Decrypting password with private key...[/dim]")
        decrypted_password = _decrypt_password(password_data, str(key_path))

        if not decrypted_password:
            console.print("\n[yellow]Could not decrypt password. Showing encrypted data:[/yellow]")
            console.print(f"[dim]Encrypted (base64): {password_data[:50]}...[/dim]")
            return

        # Display results
        table = Table(title="Windows Administrator Credentials")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Instance ID", instance_id)
        table.add_row("Region", region)
        table.add_row("Username", "Administrator")
        table.add_row("Password", f"[bold magenta]{decrypted_password}[/bold magenta]")
        if timestamp:
            table.add_row("Generated", str(timestamp)[:19])

        console.print(table)

        console.print(Panel(
            f"[bold green]RDP Connection:[/bold green]\n\n"
            f"[cyan]Username:[/cyan] Administrator\n"
            f"[cyan]Password:[/cyan] {decrypted_password}\n\n"
            f"[dim]Use this password to connect via RDP to the instance's public/private IP.[/dim]",
            title="[bold]Credentials Retrieved[/bold]",
            border_style="green"
        ))

        # Save to session
        session_mgr.save_enumeration_data("ec2_windows_password_last", {
            "instance_id": instance_id,
            "region": region,
            "username": "Administrator",
            "password": decrypted_password,
            "timestamp": str(timestamp)[:19] if timestamp else "",
        })

        console.print("\n[dim]Credentials saved to session data under 'ec2_windows_password_last'.[/dim]")

    except Exception as e:
        error_msg = str(e)
        console.print(f"[red]Failed to retrieve password data: {error_msg}[/red]")

        if "InvalidInstanceID" in error_msg:
            console.print("[yellow]Instance ID not found. Check the ID and region.[/yellow]")
        elif "UnauthorizedOperation" in error_msg or "AccessDenied" in error_msg:
            console.print("[yellow]Permission denied. Ensure ec2:GetPasswordData permission.[/yellow]")
        else:
            console.print("[yellow]Check instance ID, region, and permissions.[/yellow]")
