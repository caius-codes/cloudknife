# AWS Utilities Documentation

This directory contains utility modules for AWS operations in cloudknife.

## Overview

- **error_handling.py**: Enhanced error handling with categorization and retry logic
- **parallel.py**: Parallel execution for multi-region operations
- **regions.py**: Region resolution and client factory utilities

## error_handling.py

### Features

1. **Error Categorization**: Automatically categorizes AWS errors into meaningful categories
2. **Retry Logic**: Exponential backoff with jitter for transient errors
3. **Error Statistics**: Track and analyze error patterns

### Error Categories

- `AUTHENTICATION`: Invalid/expired credentials
- `AUTHORIZATION`: Permission denied (AccessDenied, etc.)
- `THROTTLING`: Rate limiting (retryable)
- `RESOURCE_NOT_FOUND`: Resource doesn't exist
- `VALIDATION`: Invalid parameters
- `SERVICE_ERROR`: AWS service-side issues (retryable)
- `NETWORK`: Network/connectivity issues (retryable)
- `UNKNOWN`: Unclassified errors

### Usage Examples

#### Basic Error Categorization

```python
from src.clouds.aws.utils.error_handling import categorize_error

try:
    s3_client.list_buckets()
except Exception as e:
    error = categorize_error(e)

    if error.category == ErrorCategory.AUTHORIZATION:
        console.print("Missing S3 permissions")
    elif error.category == ErrorCategory.THROTTLING:
        console.print("Rate limited - retry later")

    # Display formatted error
    console.print(error.format_for_display())
```

#### Using Retry Decorator

```python
from src.clouds.aws.utils.error_handling import with_retry, RetryConfig

# Default retry (3 attempts, exponential backoff)
@with_retry()
def list_instances(ec2_client):
    return ec2_client.describe_instances()

# Custom retry configuration
@with_retry(RetryConfig(
    max_attempts=5,
    base_delay=2.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True
))
def critical_operation(client):
    return client.some_important_call()
```

#### Safe API Calls

```python
from src.clouds.aws.utils.error_handling import safe_aws_call

# Returns (result, error) tuple
result, error = safe_aws_call(
    s3_client.list_buckets,
    default={"Buckets": []},
    log_error=True
)

if error:
    if error.category == ErrorCategory.AUTHORIZATION:
        console.print("No S3 access")
else:
    process_buckets(result)
```

#### Error Statistics

```python
from src.clouds.aws.utils.error_handling import ErrorStats, categorize_error

stats = ErrorStats()

for operation in operations:
    try:
        execute_operation(operation)
    except Exception as e:
        error = categorize_error(e)
        stats.record_error(error)

# Print summary at the end
stats.print_summary()

# Or get programmatic summary
summary = stats.get_summary()
print(f"Total errors: {summary['total_errors']}")
print(f"Retry success rate: {summary['retry_success_rate']:.1%}")
```

## parallel.py

### Features

1. **Multi-Region Parallelization**: Execute operations across AWS regions in parallel
2. **Progress Tracking**: Rich progress bars with time estimates
3. **Error Resilience**: Continue on partial failures, aggregate results
4. **Batch Execution**: Process large lists with rate limiting

### Usage Examples

#### Simple Regional Execution

```python
from src.clouds.aws.utils.parallel import execute_parallel_regional

def enumerate_ec2_instances(region: str) -> List[Dict]:
    """Count EC2 instances in a region."""
    client = boto3.client('ec2', region_name=region)
    paginator = client.get_paginator('describe_instances')

    instances = []
    for page in paginator.paginate():
        for reservation in page.get('Reservations', []):
            instances.extend(reservation.get('Instances', []))
    return instances

# Execute across regions
result = execute_parallel_regional(
    regions=['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    operation=enumerate_ec2_instances,
    operation_name="EC2 Enumeration"
)

# Get all instances from all regions
all_instances = result.get_all_items()

# Check for failures
if result.failed_regions > 0:
    print(f"Failed regions: {result.get_failed_regions()}")

# Print summary
result.print_summary()
```

#### Advanced Regional Executor

```python
from src.clouds.aws.utils.parallel import RegionalExecutor

executor = RegionalExecutor(
    max_workers=10,           # Parallel workers
    show_progress=True,       # Show progress bar
    collect_error_stats=True  # Track error statistics
)

result = executor.execute(
    regions=regions,
    operation=my_operation,
    operation_name="Lambda Enumeration",
    fail_fast=False  # Continue on errors
)

# Access detailed results
for region_result in result.results:
    if region_result.success:
        print(f"{region_result.region}: {len(region_result.data)} items")
    else:
        print(f"{region_result.region}: FAILED - {region_result.error}")

# Get error statistics
if result.error_stats:
    result.error_stats.print_summary()
```

#### Batch Execution

```python
from src.clouds.aws.utils.parallel import BatchExecutor

def process_bucket(bucket_name: str) -> Dict:
    # Process individual bucket
    return analyze_bucket(bucket_name)

executor = BatchExecutor(
    batch_size=10,              # Process 10 at a time
    delay_between_batches=1.0   # 1 second delay between batches
)

results = executor.execute(
    items=bucket_names,
    operation=process_bucket,
    max_workers=5,
    operation_name="Bucket Analysis"
)
```

### Performance Benefits

**Before (Sequential)**:
```python
# 15 regions × 2 seconds per region = 30 seconds
for region in regions:
    enumerate_region(region)
```

**After (Parallel)**:
```python
# 15 regions ÷ 8 workers × 2 seconds = ~4 seconds
result = execute_parallel_regional(regions, enumerate_region)
```

## Integration with Existing Modules

### Example: Migrating quick_enum.py

**Before**:
```python
# Sequential execution
ec2_total = 0
for region in target_regions:
    ec2 = aws_sess.client("ec2", region_name=region)
    # ... enumerate instances
    ec2_total += count
```

**After**:
```python
# Parallel execution with retry
from src.clouds.aws.utils.parallel import RegionalExecutor
from src.clouds.aws.utils.error_handling import with_retry, RetryConfig

executor = RegionalExecutor(max_workers=8, show_progress=True)

@with_retry(RetryConfig(max_attempts=3))
def enumerate_ec2_region(region: str) -> int:
    client = aws_sess.client("ec2", region_name=region)
    # ... enumerate instances
    return count

result = executor.execute(
    regions=target_regions,
    operation=enumerate_ec2_region,
    operation_name="EC2 Instances"
)

ec2_total = sum(result.get_successful_results())
```

## Best Practices

### 1. Always Use Retry for Critical Operations

```python
# Good
@with_retry(RetryConfig(max_attempts=3))
def critical_api_call():
    return client.describe_instances()

# Avoid
def risky_api_call():
    return client.describe_instances()  # No retry on throttling
```

### 2. Choose Appropriate Worker Counts

```python
# Too many workers can cause rate limiting
executor = RegionalExecutor(max_workers=50)  # ❌ BAD

# Reasonable parallelism
executor = RegionalExecutor(max_workers=min(len(regions), 10))  # ✅ GOOD
```

### 3. Handle Partial Failures Gracefully

```python
result = execute_parallel_regional(regions, operation)

if result.failed_regions > 0:
    console.print(f"[yellow]Warning: {result.failed_regions} regions failed[/yellow]")
    for failed_region in result.get_failed_regions():
        console.print(f"  • {failed_region}")

# Continue with successful results
successful_data = result.get_all_items()
```

### 4. Collect and Analyze Error Statistics

```python
error_stats = ErrorStats()

# ... perform operations and collect errors

# Analyze patterns
summary = error_stats.get_summary()

if summary['errors_by_category'].get('THROTTLING', 0) > 10:
    console.print("[yellow]High rate limiting detected - consider reducing parallelism[/yellow]")
```

### 5. Use Silent Retries in Loops

```python
# In tight loops, use silent=True to avoid noise
for action in many_actions:
    @with_retry(RetryConfig(max_attempts=2), silent=True)
    def test_action():
        return client.call_api(action)

    try:
        test_action()
    except Exception as e:
        # Handle final failure
        pass
```

## Performance Metrics

Typical improvements with parallelization:

| Operation | Before | After | Speedup |
|-----------|--------|-------|---------|
| EC2 enumeration (15 regions) | ~30s | ~4s | **7.5x** |
| Lambda functions (20 regions) | ~40s | ~5s | **8x** |
| Multi-service quick_enum | ~120s | ~18s | **6.7x** |
| IAM bruteforce (with retry) | ~90s | ~75s | **1.2x** + resilience |

## Error Handling Statistics

Example output from error statistics:

```
Error Statistics Summary
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric               ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Errors         │    45 │
│ Unique Error Codes   │     8 │
│ Total Retries        │    23 │
│ Successful Retries   │    18 │ (78.3%)
└──────────────────────┴───────┘

Errors by Category:
  • authorization: 15
  • throttling: 12
  • network: 3
```

## Troubleshooting

### Issue: Rate Limiting

```python
# Reduce parallelism
executor = RegionalExecutor(max_workers=3)  # Instead of 10

# Add delays between operations
batch_executor = BatchExecutor(
    batch_size=5,
    delay_between_batches=2.0
)
```

### Issue: Memory Usage

```python
# Process results incrementally instead of accumulating
def process_region(region):
    results = enumerate_region(region)
    # Process and discard instead of returning all data
    save_to_disk(results)
    return len(results)  # Return only count
```

### Issue: Debugging Parallel Failures

```python
# Disable parallelism for debugging
result = execute_parallel_regional(
    regions=['us-east-1'],  # Test with single region
    operation=operation,
    show_progress=False
)

# Or use sequential execution temporarily
for region in regions:
    try:
        data = operation(region)
    except Exception as e:
        print(f"Failed in {region}: {e}")
        import traceback
        traceback.print_exc()
```
