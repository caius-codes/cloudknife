from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_ecr_repositories(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate Amazon ECR repositories and a small sample of images per repository.

    For each region:
      - describe_repositories
      - for each repo, describe_images (few latest TAGGED images)

    Stores results under 'ecr_repositories' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    target_regions = resolve_regions(session_mgr, service_name="ECR")

    console.print(
        f"[bold blue]🔍 Enumerating ECR repositories in regions:[/bold blue] "
        + ", ".join(target_regions)
    )

    all_repos: List[Dict[str, Any]] = []

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)

    for region in target_regions:
        try:
            ecr = client_factory.get_client("ecr", region)

            paginator = ecr.get_paginator("describe_repositories")
            region_repos: List[Dict[str, Any]] = []
            for page in paginator.paginate():
                region_repos.extend(page.get("repositories", []))

            console.print(
                f"[green]Region {region}: found {len(region_repos)} repositories.[/green]"
            )

            for repo in region_repos:
                repo_name = repo.get("repositoryName")
                repo_uri = repo.get("repositoryUri")
                created_at = repo.get("createdAt")
                scan_cfg = repo.get("imageScanningConfiguration") or {}
                scan_on_push = scan_cfg.get("scanOnPush", False)

                # Campione di immagini TAGGED
                images_sample: List[Dict[str, Any]] = []
                try:
                    img_resp = ecr.describe_images(
                        repositoryName=repo_name,
                        maxResults=5,
                        filter={"tagStatus": "TAGGED"},
                    )
                    for img in img_resp.get("imageDetails", []):
                        tags = img.get("imageTags") or []
                        images_sample.append(
                            {
                                "Tags": tags,
                                "Digest": img.get("imageDigest"),
                                "SizeBytes": img.get("imageSizeInBytes"),
                                "PushedAt": img.get("imagePushedAt"),
                                "ScanStatus": (
                                    (img.get("imageScanStatus") or {}).get("status")
                                ),
                            }
                        )
                except Exception as e:
                    console.print(
                        f"[yellow]Failed to describe images for repo '{repo_name}' in {region}: {str(e)[:120]}[/yellow]"
                    )

                all_repos.append(
                    {
                        "RepositoryName": repo_name,
                        "Region": region,
                        "RepositoryUri": repo_uri,
                        "CreatedAt": str(created_at) if created_at else None,
                        "ScanOnPush": scan_on_push,
                        "Images": images_sample,
                    }
                )

        except Exception as e:
            console.print(
                f"[red]Failed to enumerate ECR repositories in region {region}: {str(e)}[/red]"
            )
            console.print(
                "[yellow]Ensure ecr:DescribeRepositories and ecr:DescribeImages permissions for that region.[/yellow]"
            )

    session_mgr.save_enumeration_data("ecr_repositories", all_repos)

    if not all_repos:
        console.print("[yellow]No ECR repositories found in selected regions.[/yellow]")
        return

    # Summary table
    table = Table(title=f"ECR Repositories (total: {len(all_repos)})")
    table.add_column("RepositoryName", style="cyan")
    table.add_column("Region")
    table.add_column("ScanOnPush")
    table.add_column("Images(sample)")
    table.add_column("URI")

    max_rows = 200
    for r in all_repos[:max_rows]:
        img_count = len(r.get("Images") or [])
        table.add_row(
            r["RepositoryName"] or "",
            r["Region"],
            "✅" if r.get("ScanOnPush") else "❌",
            str(img_count),
            r.get("RepositoryUri") or "",
        )

    console.print(table)

    if len(all_repos) > max_rows:
        console.print(
            f"[dim]Showing first {max_rows} repositories out of {len(all_repos)}. "
            "Full data stored under key 'ecr_repositories' in session data.[/dim]"
        )
    else:
        console.print(
            "[dim]All repositories stored under key 'ecr_repositories' in session data.[/dim]"
        )
