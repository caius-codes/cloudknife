"""
Parallel execution utilities for multi-region AWS operations.

Provides thread-safe parallelization for AWS API calls across multiple regions
with progress tracking and error handling.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Callable, List, Dict, Any, Optional, TypeVar, Generic
from dataclasses import dataclass, field
import threading

from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from .error_handling import categorize_error, AWSError, ErrorStats


console = Console()

T = TypeVar('T')


@dataclass
class RegionResult(Generic[T]):
    """Result from a region-specific operation."""

    region: str
    success: bool
    data: Optional[T] = None
    error: Optional[AWSError] = None
    execution_time: float = 0.0

    def __post_init__(self):
        """Validate result consistency."""
        if self.success and self.error is not None:
            raise ValueError("Successful result cannot have an error")
        if not self.success and self.error is None:
            raise ValueError("Failed result must have an error")


@dataclass
class ParallelExecutionResult(Generic[T]):
    """Aggregated results from parallel execution."""

    total_regions: int
    successful_regions: int
    failed_regions: int
    results: List[RegionResult[T]]
    total_items: int = 0
    error_stats: Optional[ErrorStats] = None

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_regions == 0:
            return 0.0
        return (self.successful_regions / self.total_regions) * 100

    def get_successful_results(self) -> List[T]:
        """Extract all successful results."""
        return [r.data for r in self.results if r.success and r.data is not None]

    def get_all_items(self) -> List[Any]:
        """Flatten all items from successful results (assumes data is list-like)."""
        items = []
        for result in self.results:
            if result.success and result.data:
                if isinstance(result.data, list):
                    items.extend(result.data)
                else:
                    items.append(result.data)
        return items

    def get_failed_regions(self) -> List[str]:
        """Get list of regions that failed."""
        return [r.region for r in self.results if not r.success]

    def print_summary(self, show_errors: bool = True):
        """Print execution summary to console."""
        from rich.table import Table

        # Summary stats
        console.print(f"\n[bold]Parallel Execution Summary[/bold]")
        console.print(f"  Total regions: {self.total_regions}")
        console.print(f"  Successful: [green]{self.successful_regions}[/green]")
        console.print(f"  Failed: [red]{self.failed_regions}[/red]")
        console.print(f"  Success rate: [cyan]{self.success_rate:.1f}%[/cyan]")
        console.print(f"  Total items: [cyan]{self.total_items}[/cyan]")

        # Failed regions detail
        if show_errors and self.failed_regions > 0:
            console.print(f"\n[bold red]Failed Regions:[/bold red]")
            for result in self.results:
                if not result.success and result.error:
                    console.print(f"  • {result.region}: {result.error.format_for_display()}")


class RegionalExecutor:
    """
    Execute operations across multiple AWS regions in parallel.

    Thread-safe executor with progress tracking and error handling.
    """

    def __init__(
        self,
        max_workers: Optional[int] = None,
        show_progress: bool = True,
        collect_error_stats: bool = True
    ):
        """
        Initialize regional executor.

        Args:
            max_workers: Maximum number of parallel workers (default: min(32, cpu_count + 4))
            show_progress: Show progress bar during execution
            collect_error_stats: Collect and report error statistics
        """
        self.max_workers = max_workers
        self.show_progress = show_progress
        self.collect_error_stats = collect_error_stats
        self._error_stats = ErrorStats() if collect_error_stats else None
        self._lock = threading.Lock()

    def execute(
        self,
        regions: List[str],
        operation: Callable[[str], T],
        operation_name: str = "Processing",
        fail_fast: bool = False
    ) -> ParallelExecutionResult[T]:
        """
        Execute an operation across multiple regions in parallel.

        Args:
            regions: List of AWS region names
            operation: Function that takes a region name and returns result
            operation_name: Name for progress display
            fail_fast: Stop execution on first failure

        Returns:
            ParallelExecutionResult with aggregated results

        Example:
            def enumerate_ec2_region(region: str) -> List[Dict]:
                client = boto3.client('ec2', region_name=region)
                instances = []
                paginator = client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page.get('Reservations', []):
                        instances.extend(reservation.get('Instances', []))
                return instances

            executor = RegionalExecutor()
            result = executor.execute(
                regions=['us-east-1', 'eu-west-1'],
                operation=enumerate_ec2_region,
                operation_name="EC2 Instances"
            )
        """
        if not regions:
            return ParallelExecutionResult(
                total_regions=0,
                successful_regions=0,
                failed_regions=0,
                results=[],
                error_stats=self._error_stats
            )

        results: List[RegionResult[T]] = []
        stop_event = threading.Event()

        # Determine worker count
        workers = self.max_workers or min(32, len(regions), 10)

        def execute_region(region: str) -> RegionResult[T]:
            """Execute operation for a single region."""
            if stop_event.is_set():
                return RegionResult(
                    region=region,
                    success=False,
                    error=AWSError(
                        category="unknown",
                        code="Cancelled",
                        message="Execution cancelled due to fail_fast",
                        is_retryable=False
                    )
                )

            import time
            start_time = time.time()

            try:
                data = operation(region)
                execution_time = time.time() - start_time

                return RegionResult(
                    region=region,
                    success=True,
                    data=data,
                    execution_time=execution_time
                )

            except Exception as e:
                execution_time = time.time() - start_time
                error = categorize_error(e)

                if self._error_stats:
                    with self._lock:
                        self._error_stats.record_error(error)

                if fail_fast:
                    stop_event.set()

                return RegionResult(
                    region=region,
                    success=False,
                    error=error,
                    execution_time=execution_time
                )

        # Execute with progress tracking
        if self.show_progress:
            results = self._execute_with_progress(
                regions, execute_region, operation_name, workers
            )
        else:
            results = self._execute_without_progress(
                regions, execute_region, workers
            )

        # Calculate statistics
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        total_items = sum(
            len(r.data) if r.success and isinstance(r.data, list) else (1 if r.success else 0)
            for r in results
        )

        return ParallelExecutionResult(
            total_regions=len(regions),
            successful_regions=successful,
            failed_regions=failed,
            results=results,
            total_items=total_items,
            error_stats=self._error_stats
        )

    def _execute_with_progress(
        self,
        regions: List[str],
        operation: Callable[[str], RegionResult[T]],
        operation_name: str,
        workers: int
    ) -> List[RegionResult[T]]:
        """Execute with progress bar."""
        results: List[RegionResult[T]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]{operation_name}[/cyan]",
                total=len(regions)
            )

            with ThreadPoolExecutor(max_workers=workers) as executor:
                # Submit all tasks
                future_to_region = {
                    executor.submit(operation, region): region
                    for region in regions
                }

                # Collect results as they complete
                for future in as_completed(future_to_region):
                    result = future.result()
                    results.append(result)
                    progress.update(task, advance=1)

        return results

    def _execute_without_progress(
        self,
        regions: List[str],
        operation: Callable[[str], RegionResult[T]],
        workers: int
    ) -> List[RegionResult[T]]:
        """Execute without progress bar."""
        results: List[RegionResult[T]] = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_region = {
                executor.submit(operation, region): region
                for region in regions
            }

            for future in as_completed(future_to_region):
                result = future.result()
                results.append(result)

        return results


def execute_parallel_regional(
    regions: List[str],
    operation: Callable[[str], T],
    max_workers: Optional[int] = None,
    show_progress: bool = True,
    operation_name: str = "Processing regions"
) -> ParallelExecutionResult[T]:
    """
    Convenience function for parallel regional execution.

    Args:
        regions: List of region names
        operation: Function that takes region and returns data
        max_workers: Max parallel workers
        show_progress: Show progress bar
        operation_name: Name for display

    Returns:
        ParallelExecutionResult with aggregated data

    Example:
        result = execute_parallel_regional(
            regions=['us-east-1', 'eu-west-1'],
            operation=lambda r: enumerate_ec2(r),
            operation_name="EC2 Enumeration"
        )

        all_instances = result.get_all_items()
    """
    executor = RegionalExecutor(
        max_workers=max_workers,
        show_progress=show_progress
    )

    return executor.execute(
        regions=regions,
        operation=operation,
        operation_name=operation_name
    )


class BatchExecutor:
    """
    Execute operations in batches with configurable batch size.

    Useful for operations with strict rate limits or when processing
    large numbers of items.
    """

    def __init__(self, batch_size: int = 10, delay_between_batches: float = 0.0):
        """
        Initialize batch executor.

        Args:
            batch_size: Number of items to process in each batch
            delay_between_batches: Delay in seconds between batches
        """
        self.batch_size = batch_size
        self.delay_between_batches = delay_between_batches

    def execute(
        self,
        items: List[Any],
        operation: Callable[[Any], T],
        max_workers: Optional[int] = None,
        show_progress: bool = True,
        operation_name: str = "Processing items"
    ) -> List[T]:
        """
        Execute operation on items in batches.

        Args:
            items: List of items to process
            operation: Function to apply to each item
            max_workers: Max parallel workers per batch
            show_progress: Show progress bar
            operation_name: Name for display

        Returns:
            List of results (may include None for failed items)
        """
        import time

        results: List[T] = []
        workers = max_workers or min(self.batch_size, 10)

        # Split into batches
        batches = [
            items[i:i + self.batch_size]
            for i in range(0, len(items), self.batch_size)
        ]

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]{operation_name}[/cyan]",
                    total=len(items)
                )

                for batch in batches:
                    batch_results = self._execute_batch(batch, operation, workers)
                    results.extend(batch_results)
                    progress.update(task, advance=len(batch))

                    if self.delay_between_batches > 0:
                        time.sleep(self.delay_between_batches)
        else:
            for batch in batches:
                batch_results = self._execute_batch(batch, operation, workers)
                results.extend(batch_results)

                if self.delay_between_batches > 0:
                    time.sleep(self.delay_between_batches)

        return results

    def _execute_batch(
        self,
        batch: List[Any],
        operation: Callable[[Any], T],
        workers: int
    ) -> List[T]:
        """Execute a single batch."""
        results = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(operation, item) for item in batch]

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    # Skip failed items
                    results.append(None)

        return results
