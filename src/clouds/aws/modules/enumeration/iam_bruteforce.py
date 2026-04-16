import datetime
from typing import List, Dict, Optional, Tuple, Any
from botocore.exceptions import ClientError, ParamValidationError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ...aws_session import AWSSessionManager
from src.data.iam_actions_wordlist import get_profile_actions
from src.data.aws_privesc_techniques import is_dangerous_permission
from src.clouds.aws.utils.error_handling import (
    categorize_error,
    ErrorCategory,
    with_retry,
    RetryConfig,
    ErrorStats
)


console = Console()


# Mapping action -> (boto3 method, parameters) for the "fast" (base) profile.
FAST_CALL_MAPPING: Dict[str, Dict[str, Tuple[str, Dict[str, Any]]]] = {
    "iam": {
        "ListUsers": ("list_users", {}),
        "ListRoles": ("list_roles", {}),
        "ListGroups": ("list_groups", {}),
        "ListPolicies": ("list_policies", {"Scope": "All", "MaxItems": 100}),
        "GetUser": ("get_user", {}),
        "GetAccountSummary": ("get_account_summary", {}),
        "ListRolePolicies": ("list_role_policies", {"RoleName": "DOES_NOT_EXIST_ROLE"}),
        "ListAttachedUserPolicies": (
            "list_attached_user_policies",
            {"UserName": "DOES_NOT_EXIST_USER"},
        ),
        "ListAttachedRolePolicies": (
            "list_attached_role_policies",
            {"RoleName": "DOES_NOT_EXIST_ROLE"},
        ),
        "ListAccessKeys": (
            "list_access_keys",
            {"UserName": "DOES_NOT_EXIST_USER"},
        ),
        "CreateAccessKey": (
            "create_access_key",
            {"UserName": "DOES_NOT_EXIST_USER"},
        ),
        "DeleteAccessKey": (
            "delete_access_key",
            {"UserName": "DOES_NOT_EXIST_USER", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"},
        ),
        # Top priority additions from aws-enumerator
        "GetAccountAuthorizationDetails": ("get_account_authorization_details", {}),
        "GetCredentialReport": ("get_credential_report", {}),
        "GetAccountPasswordPolicy": ("get_account_password_policy", {}),
        "ListInstanceProfiles": ("list_instance_profiles", {"MaxItems": 100}),
        "ListMFADevices": ("list_mfa_devices", {"MaxItems": 100}),
        "ListVirtualMFADevices": ("list_virtual_mfa_devices", {"MaxItems": 100}),
        "ListAccountAliases": ("list_account_aliases", {"MaxItems": 100}),
    },
    "sts": {
        "GetCallerIdentity": ("get_caller_identity", {}),
        "GetSessionToken": ("get_session_token", {"DurationSeconds": 900}),
    },
    "s3": {
        "ListBuckets": ("list_buckets", {}),
        "ListMultipartUploads": (
            "list_multipart_uploads",
            {"Bucket": "nonexistent-bucket-for-perm-check"},
        ),
    },
    "ec2": {
        "DescribeInstances": ("describe_instances", {"MaxResults": 5}),
        "DescribeRegions": ("describe_regions", {}),
        "DescribeVpcs": ("describe_vpcs", {"MaxResults": 5}),
        "DescribeSecurityGroups": ("describe_security_groups", {"MaxResults": 5}),
        "DescribeSubnets": ("describe_subnets", {"MaxResults": 5}),
        "DescribeVolumes": ("describe_volumes", {"MaxResults": 5}),
        "DescribeNetworkInterfaces": (
            "describe_network_interfaces",
            {"MaxResults": 5},
        ),
    },
    "cloudtrail": {
        "DescribeTrails": ("describe_trails", {}),
        "GetEventSelectors": ("get_event_selectors", {"TrailName": "DOES_NOT_EXIST_TRAIL"}),
    },
    "logs": {
        "DescribeLogGroups": ("describe_log_groups", {"limit": 5}),
        "DescribeLogStreams": (
            "describe_log_streams",
            {"logGroupName": "DOES_NOT_EXIST_GROUP", "limit": 5},
        ),
    },
    "config": {
        "DescribeConfigurationRecorders": ("describe_configuration_recorders", {}),
        "DescribeConfigurationRecorderStatus": ("describe_configuration_recorder_status", {}),
    },
    "lambda": {
        "ListFunctions": ("list_functions", {"MaxItems": 50}),
        "ListEventSourceMappings": (
            "list_event_source_mappings",
            {"MaxItems": 50},
        ),
    },
    "rds": {
        "DescribeDBInstances": ("describe_db_instances", {"MaxRecords": 20}),
        "DescribeDBClusters": ("describe_db_clusters", {}),
    },
    "secretsmanager": {
        "ListSecrets": ("list_secrets", {"MaxResults": 20}),
        "DescribeSecret": ("describe_secret", {"SecretId": "DOES_NOT_EXIST_SECRET"}),
        "GetSecretValue": ("get_secret_value", {"SecretId": "DOES_NOT_EXIST_SECRET"}),
    },
    "kms": {
        "ListKeys": ("list_keys", {"Limit": 20}),
        "DescribeKey": (
            "describe_key",
            {"KeyId": "00000000-0000-0000-0000-000000000000"},
        ),
    },
    "organizations": {
        "DescribeOrganization": ("describe_organization", {}),
        "ListAccounts": ("list_accounts", {"MaxResults": 20}),
    },
}


# Extended mapping for the "full" profile.
# Dove possibile riusiamo le stesse chiamate del fast,
# aggiungendo le nuove azioni introdotte in FULL_ACTIONS.
FULL_CALL_MAPPING: Dict[str, Dict[str, Tuple[str, Dict[str, Any]]]] = {
    # IAM (esteso con tutte le 13 nuove azioni da aws-enumerator)
    "iam": {
        **FAST_CALL_MAPPING["iam"],
        # Additional IAM permissions for FULL mode
        "ListOpenIDConnectProviders": ("list_open_id_connect_providers", {}),
        "ListSAMLProviders": ("list_saml_providers", {}),
        "ListServerCertificates": ("list_server_certificates", {"MaxItems": 100}),
        "ListServiceSpecificCredentials": (
            "list_service_specific_credentials",
            {"UserName": "DOES_NOT_EXIST_USER"},
        ),
        "ListSSHPublicKeys": ("list_ssh_public_keys", {"UserName": "DOES_NOT_EXIST_USER"}),
        "ListSigningCertificates": (
            "list_signing_certificates",
            {"UserName": "DOES_NOT_EXIST_USER"},
        ),
    },

    "sts": FAST_CALL_MAPPING["sts"],

    # S3 (stesso mapping del fast, per ora)
    "s3": FAST_CALL_MAPPING["s3"],

    # EC2 – esteso con le azioni aggiuntive
    "ec2": {
        # fast
        "DescribeInstances": ("describe_instances", {"MaxResults": 5}),
        "DescribeRegions": ("describe_regions", {}),
        "DescribeVpcs": ("describe_vpcs", {"MaxResults": 5}),
        "DescribeSecurityGroups": ("describe_security_groups", {"MaxResults": 5}),
        "DescribeSubnets": ("describe_subnets", {"MaxResults": 5}),
        "DescribeVolumes": ("describe_volumes", {"MaxResults": 5}),
        "DescribeNetworkInterfaces": (
            "describe_network_interfaces",
            {"MaxResults": 5},
        ),
        # full-extra
        "DescribeAccountAttributes": ("describe_account_attributes", {}),
        "DescribeAvailabilityZones": ("describe_availability_zones", {}),
        "DescribeSnapshots": ("describe_snapshots", {"MaxResults": 5}),
        "DescribeAddresses": ("describe_addresses", {"MaxResults": 5}),
        "DescribeInstanceAttribute": (
            "describe_instance_attribute",
            {"InstanceId": "i-00000000000000000", "Attribute": "instanceType"},
        ),
        "DescribeInternetGateways": ("describe_internet_gateways", {"MaxResults": 5}),
        "DescribeNatGateways": ("describe_nat_gateways", {"MaxResults": 5}),
        "DescribeRouteTables": ("describe_route_tables", {"MaxResults": 5}),
        "DescribeVpcEndpoints": ("describe_vpc_endpoints", {"MaxResults": 5}),
        "DescribeVpcEndpointServices": ("describe_vpc_endpoint_services", {"MaxResults": 5}),
        "DescribeFlowLogs": ("describe_flow_logs", {"MaxResults": 5}),
        "DescribeNetworkAcls": ("describe_network_acls", {"MaxResults": 5}),
        "DescribePlacementGroups": ("describe_placement_groups", {}),
        "DescribeImages": ("describe_images", {"Owners": ["self"], "MaxResults": 5}),
        "DescribeKeyPairs": ("describe_key_pairs", {}),
        "DescribeVpnGateways": ("describe_vpn_gateways", {"MaxResults": 5}),
        "DescribeVpnConnections": ("describe_vpn_connections", {"MaxResults": 5}),
        "DescribeCustomerGateways": ("describe_customer_gateways", {"MaxResults": 5}),
        # Additions from aws-enumerator
        "DescribeIamInstanceProfileAssociations": (
            "describe_iam_instance_profile_associations",
            {"MaxResults": 5},
        ),
        "DescribeLaunchTemplates": ("describe_launch_templates", {"MaxResults": 5}),
        "DescribeTags": ("describe_tags", {"MaxResults": 5}),
    },

    # CloudTrail
    "cloudtrail": {
        "DescribeTrails": ("describe_trails", {}),
        "GetTrailStatus": ("get_trail_status", {"Name": "DOES_NOT_EXIST_TRAIL"}),
        "GetEventSelectors": ("get_event_selectors", {"TrailName": "DOES_NOT_EXIST_TRAIL"}),
        "ListTrails": ("list_trails", {}),
    },

    # CloudWatch Logs
    "logs": {
        "DescribeLogGroups": ("describe_log_groups", {"limit": 5}),
        "DescribeLogStreams": (
            "describe_log_streams",
            {"logGroupName": "DOES_NOT_EXIST_GROUP", "limit": 5},
        ),
        "FilterLogEvents": (
            "filter_log_events",
            {"logGroupName": "DOES_NOT_EXIST_GROUP", "limit": 5},
        ),
        "DescribeMetricFilters": (
            "describe_metric_filters",
            {"logGroupName": "DOES_NOT_EXIST_GROUP"},
        ),
    },

    # Config
    "config": {
        "DescribeConfigurationRecorders": ("describe_configuration_recorders", {}),
        "DescribeConfigurationRecorderStatus": ("describe_configuration_recorder_status", {}),
        "DescribeConfigurationAggregatorSourcesStatus": (
            "describe_configuration_aggregator_sources_status",
            {"ConfigurationAggregatorName": "DOES_NOT_EXIST_AGG"},
        ),
        "DescribeOrganizationConfigRules": ("describe_organization_config_rules", {}),
        "DescribeDeliveryChannels": ("describe_delivery_channels", {}),
    },

    # Lambda
    "lambda": {
        "ListFunctions": ("list_functions", {"MaxItems": 50}),
        "GetAccountSettings": ("get_account_settings", {}),
        "ListEventSourceMappings": ("list_event_source_mappings", {"MaxItems": 50}),
        "ListAliases": (
            "list_aliases",
            {"FunctionName": "DOES_NOT_EXIST_FUNCTION"},
        ),
        "ListLayers": ("list_layers", {"MaxItems": 25}),
        "ListLayerVersions": (
            "list_layer_versions",
            {"LayerName": "DOES_NOT_EXIST_LAYER"},
        ),
        "ListProvisionedConcurrencyConfigs": (
            "list_provisioned_concurrency_configs",
            {"FunctionName": "DOES_NOT_EXIST_FUNCTION"},
        ),
        "ListFunctionEventInvokeConfigs": (
            "list_function_event_invoke_configs",
            {"FunctionName": "DOES_NOT_EXIST_FUNCTION"},
        ),
    },

    # RDS
    "rds": {
        "DescribeDBInstances": ("describe_db_instances", {"MaxRecords": 20}),
        "DescribeDBClusters": ("describe_db_clusters", {}),
        "DescribeDBSubnetGroups": ("describe_db_subnet_groups", {"MaxRecords": 20}),
        "DescribeDBSecurityGroups": ("describe_db_security_groups", {"MaxRecords": 20}),
        "DescribeDBParameterGroups": ("describe_db_parameter_groups", {"MaxRecords": 20}),
        "DescribeEvents": ("describe_events", {}),
        "DescribePendingMaintenanceActions": (
            "describe_pending_maintenance_actions",
            {},
        ),
        "DescribeDBClusterSnapshots": ("describe_db_cluster_snapshots", {"MaxRecords": 20}),
        "DescribeDBSnapshots": ("describe_db_snapshots", {"MaxRecords": 20}),
    },

    # Secrets Manager
    "secretsmanager": {
        "ListSecrets": ("list_secrets", {"MaxResults": 20}),
        "DescribeSecret": ("describe_secret", {"SecretId": "DOES_NOT_EXIST_SECRET"}),
        "GetRandomPassword": ("get_random_password", {"PasswordLength": 12}),
        "GetSecretValue": ("get_secret_value", {"SecretId": "DOES_NOT_EXIST_SECRET"}),
    },

    # KMS
    "kms": {
        "ListKeys": ("list_keys", {"Limit": 20}),
        "DescribeKey": (
            "describe_key",
            {"KeyId": "00000000-0000-0000-0000-000000000000"},
        ),
        "ListAliases": ("list_aliases", {"Limit": 25}),
        "ListGrants": (
            "list_grants",
            {"KeyId": "00000000-0000-0000-0000-000000000000", "Limit": 10},
        ),
        "ListKeyPolicies": (
            "list_key_policies",
            {"KeyId": "00000000-0000-0000-0000-000000000000"},
        ),
    },

    # Organizations
    "organizations": {
        "DescribeOrganization": ("describe_organization", {}),
        "ListAccounts": ("list_accounts", {"MaxResults": 20}),
        "ListRoots": ("list_roots", {}),
        "ListPolicies": ("list_policies", {"Filter": "SERVICE_CONTROL_POLICY"}),
        "ListPoliciesForTarget": (
            "list_policies_for_target",
            {"TargetId": "000000000000", "Filter": "SERVICE_CONTROL_POLICY"},
        ),
        "ListTargetsForPolicy": (
            "list_targets_for_policy",
            {"PolicyId": "p-00000000"},
        ),
    },

    # DynamoDB (nuovo blocco full)
    "dynamodb": {
        "ListTables": ("list_tables", {"Limit": 1}),
        "DescribeTable": (
            "describe_table",
            {"TableName": "DOES_NOT_EXIST_TABLE"},
        ),
        "Scan": (
            "scan",
            {"TableName": "DOES_NOT_EXIST_TABLE", "Limit": 1},
        ),
        "Query": (
            "query",
            {
                "TableName": "DOES_NOT_EXIST_TABLE",
                "KeyConditionExpression": "pk = :v",
                "ExpressionAttributeValues": {":v": {"S": "test"}},
                "Limit": 1,
            },
        ),
        "GetItem": (
            "get_item",
            {
                "TableName": "DOES_NOT_EXIST_TABLE",
                "Key": {"pk": {"S": "test"}},
            },
        ),
        "BatchGetItem": (
            "batch_get_item",
            {
                "RequestItems": {
                    "DOES_NOT_EXIST_TABLE": {
                        "Keys": [{"pk": {"S": "test"}}],
                        "ConsistentRead": False,
                    }
                }
            },
        ),
        # Additions from aws-enumerator
        "ListBackups": ("list_backups", {"Limit": 10}),
        "ListGlobalTables": ("list_global_tables", {"Limit": 10}),
    },

     # ECS (fast profile: only the main list actions from the wordlist)
    "ecs": {
        "ListServices": ("list_services", {}),
        "DescribeClusters": ("describe_clusters", {}),
        "ListClusters": ("list_clusters", {}),
        "ListTasks": ("list_tasks", {}),
        "ListTaskDefinitions": ("list_task_definitions", {}),
        "ListContainerInstances": ("list_container_instances", {}),
        "ListAccountSettings": ("list_account_settings", {}),
        "ListTaskDefinitionFamilies": ("list_task_definition_families", {}),
    },

    # ECR (Elastic Container Registry) - from aws-enumerator
    "ecr": {
        "DescribeRepositories": ("describe_repositories", {"maxResults": 100}),
        "ListImages": (
            "list_images",
            {"repositoryName": "DOES_NOT_EXIST_REPO", "maxResults": 100},
        ),
        "GetAuthorizationToken": ("get_authorization_token", {}),
        "DescribeImages": (
            "describe_images",
            {"repositoryName": "DOES_NOT_EXIST_REPO", "maxResults": 100},
        ),
    },

    # EKS (Kubernetes) - from aws-enumerator
    "eks": {
        "ListClusters": ("list_clusters", {"maxResults": 100}),
        "DescribeCluster": ("describe_cluster", {"name": "DOES_NOT_EXIST_CLUSTER"}),
        "ListNodegroups": (
            "list_nodegroups",
            {"clusterName": "DOES_NOT_EXIST_CLUSTER", "maxResults": 100},
        ),
        "DescribeNodegroup": (
            "describe_nodegroup",
            {"clusterName": "DOES_NOT_EXIST_CLUSTER", "nodegroupName": "DOES_NOT_EXIST_NG"},
        ),
    },

    # SNS (Simple Notification Service) - from aws-enumerator
    "sns": {
        "ListTopics": ("list_topics", {}),
        "ListSubscriptions": ("list_subscriptions", {}),
        "GetTopicAttributes": (
            "get_topic_attributes",
            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:DOES_NOT_EXIST"},
        ),
        "ListTagsForResource": (
            "list_tags_for_resource",
            {"ResourceArn": "arn:aws:sns:us-east-1:123456789012:DOES_NOT_EXIST"},
        ),
    },

    # SQS (Simple Queue Service) - from aws-enumerator
    "sqs": {
        "ListQueues": ("list_queues", {"MaxResults": 100}),
        "GetQueueAttributes": (
            "get_queue_attributes",
            {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/DOES_NOT_EXIST"},
        ),
        "ListQueueTags": (
            "list_queue_tags",
            {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/DOES_NOT_EXIST"},
        ),
    },

    # CloudFormation - from aws-enumerator
    "cloudformation": {
        "ListStacks": ("list_stacks", {}),
        "DescribeStacks": ("describe_stacks", {}),
        "ListStackResources": (
            "list_stack_resources",
            {"StackName": "DOES_NOT_EXIST_STACK"},
        ),
        "DescribeStackResources": (
            "describe_stack_resources",
            {"StackName": "DOES_NOT_EXIST_STACK"},
        ),
    },

    # GuardDuty - from aws-enumerator
    "guardduty": {
        "ListDetectors": ("list_detectors", {"MaxResults": 50}),
        "GetDetector": ("get_detector", {"DetectorId": "00000000000000000000000000000000"}),
        "ListFindings": (
            "list_findings",
            {"DetectorId": "00000000000000000000000000000000", "MaxResults": 50},
        ),
        "GetFindings": (
            "get_findings",
            {
                "DetectorId": "00000000000000000000000000000000",
                "FindingIds": ["00000000000000000000000000000000"],
            },
        ),
    },

    # Security Hub - from aws-enumerator
    "securityhub": {
        "DescribeHub": ("describe_hub", {}),
        "GetFindings": ("get_findings", {"MaxResults": 100}),
        "ListEnabledProductsForImport": ("list_enabled_products_for_import", {}),
    },

    # SSM (Systems Manager) - from aws-enumerator
    "ssm": {
        "DescribeInstanceInformation": (
            "describe_instance_information",
            {"MaxResults": 50},
        ),
        "ListCommands": ("list_commands", {"MaxResults": 25}),
        "GetParameter": ("get_parameter", {"Name": "DOES_NOT_EXIST_PARAM"}),
        "DescribeParameters": ("describe_parameters", {"MaxResults": 50}),
        "ListDocuments": ("list_documents", {"MaxResults": 25}),
    },
}


# Mapping for the "low" profile - lower priority services
LOW_CALL_MAPPING: Dict[str, Dict[str, Tuple[str, Dict[str, Any]]]] = {
    # API Gateway
    "apigateway": {
        "GetRestApis": ("get_rest_apis", {"limit": 100}),
        "GetResources": (
            "get_resources",
            {"restApiId": "DOES_NOT_EXIST_API", "limit": 100},
        ),
        "GetStages": ("get_stages", {"restApiId": "DOES_NOT_EXIST_API"}),
        "GetApiKeys": ("get_api_keys", {"limit": 100}),
    },

    # AppSync
    "appsync": {
        "ListGraphqlApis": ("list_graphql_apis", {"maxResults": 25}),
        "ListApiKeys": ("list_api_keys", {"apiId": "DOES_NOT_EXIST_API", "maxResults": 25}),
        "ListDataSources": (
            "list_data_sources",
            {"apiId": "DOES_NOT_EXIST_API", "maxResults": 25},
        ),
    },

    # EventBridge
    "events": {
        "ListRules": ("list_rules", {"Limit": 100}),
        "ListEventBuses": ("list_event_buses", {"Limit": 100}),
        "ListTargetsByRule": ("list_targets_by_rule", {"Rule": "DOES_NOT_EXIST_RULE"}),
    },

    # Athena
    "athena": {
        "ListWorkGroups": ("list_work_groups", {"MaxResults": 50}),
        "ListDataCatalogs": ("list_data_catalogs", {"MaxResults": 50}),
        "ListQueryExecutions": ("list_query_executions", {"MaxResults": 50}),
    },

    # Glue
    "glue": {
        "GetDatabases": ("get_databases", {"MaxResults": 100}),
        "GetTables": (
            "get_tables",
            {"DatabaseName": "DOES_NOT_EXIST_DB", "MaxResults": 100},
        ),
        "GetCrawlers": ("get_crawlers", {"MaxResults": 100}),
        "ListJobs": ("list_jobs", {"MaxResults": 100}),
    },

    # Redshift
    "redshift": {
        "DescribeClusters": ("describe_clusters", {"MaxRecords": 100}),
        "DescribeClusterSnapshots": ("describe_cluster_snapshots", {"MaxRecords": 100}),
        "DescribeClusterParameterGroups": (
            "describe_cluster_parameter_groups",
            {"MaxRecords": 100},
        ),
    },

    # Kinesis
    "kinesis": {
        "ListStreams": ("list_streams", {"Limit": 100}),
        "DescribeStream": ("describe_stream", {"StreamName": "DOES_NOT_EXIST_STREAM"}),
        "ListStreamConsumers": (
            "list_stream_consumers",
            {"StreamARN": "arn:aws:kinesis:us-east-1:123456789012:stream/DOES_NOT_EXIST"},
        ),
    },

    # Route53
    # Fake zone ID uses valid format (13 uppercase alphanumeric) → NoSuchHostedZone → ALLOWED.
    # Using a malformed ID would return InvalidInput → falls to ALLOWED as a false positive.
    "route53": {
        # ── List (no required params) ────────────────────────────────────────
        "ListHostedZones": ("list_hosted_zones", {"MaxItems": "100"}),
        "ListHealthChecks": ("list_health_checks", {"MaxItems": "100"}),
        "ListGeoLocations": ("list_geo_locations", {}),
        "ListReusableDelegationSets": ("list_reusable_delegation_sets", {}),
        "ListQueryLoggingConfigs": ("list_query_logging_configs", {}),
        "ListTrafficPolicies": ("list_traffic_policies", {}),
        "ListTrafficPolicyInstances": ("list_traffic_policy_instances", {}),
        "ListCidrCollections": ("list_cidr_collections", {}),
        # ── Get (no required params) ─────────────────────────────────────────
        "GetCheckerIpRanges": ("get_checker_ip_ranges", {}),
        "GetHealthCheckCount": ("get_health_check_count", {}),
        "GetHostedZoneCount": ("get_hosted_zone_count", {}),
        "GetTrafficPolicyInstanceCount": ("get_traffic_policy_instance_count", {}),
        # GetAccountLimit: returns real limit data (not a not-found) → ALLOWED means permission granted.
        "GetAccountLimit": ("get_account_limit", {"Type": "MAX_HOSTED_ZONES_BY_OWNER"}),
        # ── Get / List (fake zone/check ID → NoSuchHostedZone → ALLOWED) ────
        "GetHostedZone": ("get_hosted_zone", {"Id": "Z000000000000"}),
        "GetDNSSEC": ("get_dnssec", {"HostedZoneId": "Z000000000000"}),
        "GetHealthCheck": (
            "get_health_check",
            {"HealthCheckId": "00000000-0000-0000-0000-000000000000"},
        ),
        "ListResourceRecordSets": (
            "list_resource_record_sets",
            {"HostedZoneId": "Z000000000000"},
        ),
        "ListVpcAssociationAuthorizations": (
            "list_vpc_association_authorizations",
            {"HostedZoneId": "Z000000000000"},
        ),
    },

    # ELB (Classic)
    "elb": {
        "DescribeLoadBalancers": ("describe_load_balancers", {}),
        "DescribeTags": (
            "describe_tags",
            {"LoadBalancerNames": ["DOES_NOT_EXIST_LB"]},
        ),
        "DescribeTargetGroups": ("describe_target_groups", {}),
    },

    # ELBv2 (Application/Network Load Balancers)
    "elbv2": {
        "DescribeLoadBalancers": ("describe_load_balancers", {}),
        "DescribeTargetGroups": ("describe_target_groups", {}),
        "DescribeListeners": (
            "describe_listeners",
            {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/DOES_NOT_EXIST/0000000000000000"},
        ),
        "DescribeTags": (
            "describe_tags",
            {"ResourceArns": ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/DOES_NOT_EXIST/0000000000000000"]},
        ),
    },

    # EFS
    "efs": {
        "DescribeFileSystems": ("describe_file_systems", {"MaxItems": 100}),
        "DescribeMountTargets": (
            "describe_mount_targets",
            {"FileSystemId": "fs-00000000"},
        ),
        "DescribeAccessPoints": ("describe_access_points", {"MaxResults": 100}),
    },

    # Glacier
    "glacier": {
        "ListVaults": ("list_vaults", {"limit": "100"}),
        "DescribeVault": ("describe_vault", {"vaultName": "DOES_NOT_EXIST_VAULT"}),
    },

    # Storage Gateway
    "storagegateway": {
        "ListGateways": ("list_gateways", {"Limit": 100}),
        "DescribeGatewayInformation": (
            "describe_gateway_information",
            {"GatewayARN": "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-00000000"},
        ),
        "ListVolumes": ("list_volumes", {"Limit": 100}),
    },

    # Batch
    "batch": {
        "DescribeComputeEnvironments": ("describe_compute_environments", {"maxResults": 100}),
        "DescribeJobQueues": ("describe_job_queues", {"maxResults": 100}),
        "DescribeJobDefinitions": ("describe_job_definitions", {"maxResults": 100}),
    },

    # Lightsail
    "lightsail": {
        "GetInstances": ("get_instances", {}),
        "GetDomains": ("get_domains", {}),
        "GetLoadBalancers": ("get_load_balancers", {}),
    },

    # OpenSearch
    "opensearch": {
        "ListDomainNames": ("list_domain_names", {}),
        "DescribeDomain": ("describe_domain", {"DomainName": "DOES_NOT_EXIST_DOMAIN"}),
    },

    # Cognito Identity Provider
    "cognito-idp": {
        "ListUserPools": ("list_user_pools", {"MaxResults": 60}),
        "ListIdentityPools": ("list_identity_pools", {"MaxResults": 60}),
        "ListUsers": (
            "list_users",
            {"UserPoolId": "us-east-1_00000000", "Limit": 60},
        ),
    },

    # CloudWatch
    "cloudwatch": {
        "ListMetrics": ("list_metrics", {}),
        "DescribeAlarms": ("describe_alarms", {"MaxRecords": 100}),
        "DescribeAlarmsForMetric": (
            "describe_alarms_for_metric",
            {"MetricName": "DOES_NOT_EXIST_METRIC", "Namespace": "AWS/EC2"},
        ),
    },

    # ACM
    "acm": {
        "ListCertificates": ("list_certificates", {"MaxItems": 1000}),
        "DescribeCertificate": (
            "describe_certificate",
            {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"},
        ),
    },

    # WAF (Classic)
    "waf": {
        "ListWebACLs": ("list_web_acls", {"Limit": 100}),
        "ListRules": ("list_rules", {"Limit": 100}),
    },

    # WAFv2
    "wafv2": {
        "ListWebACLs": ("list_web_acls", {"Scope": "REGIONAL", "Limit": 100}),
        "ListRuleGroups": ("list_rule_groups", {"Scope": "REGIONAL", "Limit": 100}),
        "ListIPSets": ("list_ip_sets", {"Scope": "REGIONAL", "Limit": 100}),
    },

    # Ground Station (satellite communication — niche, regional service)
    # NOTE: CreateConfig/CreateDataflowEndpointGroup/CreateMissionProfile and ReserveContact
    # are intentionally excluded: they have no resource-dependency to produce a safe
    # NotFoundException, so calling them with valid params would create real resources.
    "groundstation": {
        # ── List (no required params) ───────────────────────────────────────
        "ListConfigs": ("list_configs", {}),
        "ListGroundStations": ("list_ground_stations", {}),
        "ListMissionProfiles": ("list_mission_profiles", {}),
        "ListSatellites": ("list_satellites", {}),
        "ListDataflowEndpointGroups": ("list_dataflow_endpoint_groups", {}),
        # ListContacts: endTime/startTime/statusList required.
        # COMPLETED avoids needing groundStation/missionProfileArn/satelliteArn.
        "ListContacts": (
            "list_contacts",
            {
                "endTime": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                "startTime": datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
                "statusList": ["COMPLETED"],
            },
        ),
        # ListEphemerides: satelliteId + date range required.
        "ListEphemerides": (
            "list_ephemerides",
            {
                "satelliteId": "00000000-0000-0000-0000-000000000000",
                "startTime": datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
                "endTime": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            },
        ),
        # ListTagsForResource: fake mission-profile ARN → NotFoundException → ALLOWED.
        "ListTagsForResource": (
            "list_tags_for_resource",
            {"resourceArn": "arn:aws:groundstation:us-east-2:000000000000:mission-profile/00000000-0000-0000-0000-000000000000"},
        ),
        # ── Get (fake UUID → NotFoundException → ALLOWED) ───────────────────
        "GetMinuteUsage": ("get_minute_usage", {"month": 1, "year": 2024}),
        "GetConfig": (
            "get_config",
            {"configId": "00000000-0000-0000-0000-000000000000", "configType": "tracking"},
        ),
        "GetDataflowEndpointGroup": (
            "get_dataflow_endpoint_group",
            {"dataflowEndpointGroupId": "00000000-0000-0000-0000-000000000000"},
        ),
        "GetMissionProfile": (
            "get_mission_profile",
            {"missionProfileId": "00000000-0000-0000-0000-000000000000"},
        ),
        "GetSatellite": (
            "get_satellite",
            {"satelliteId": "00000000-0000-0000-0000-000000000000"},
        ),
        "GetAgentConfiguration": (
            "get_agent_configuration",
            {"agentId": "00000000-0000-0000-0000-000000000000"},
        ),
        # ── Describe (fake UUID → NotFoundException → ALLOWED) ──────────────
        "DescribeContact": (
            "describe_contact",
            {"contactId": "00000000-0000-0000-0000-000000000000"},
        ),
        "DescribeEphemeris": (
            "describe_ephemeris",
            {"ephemerisId": "00000000-0000-0000-0000-000000000000"},
        ),
        # ── Delete / Cancel (fake UUID → NotFoundException → ALLOWED) ───────
        "CancelContact": (
            "cancel_contact",
            {"contactId": "00000000-0000-0000-0000-000000000000"},
        ),
        "DeleteConfig": (
            "delete_config",
            {"configId": "00000000-0000-0000-0000-000000000000", "configType": "tracking"},
        ),
        "DeleteDataflowEndpointGroup": (
            "delete_dataflow_endpoint_group",
            {"dataflowEndpointGroupId": "00000000-0000-0000-0000-000000000000"},
        ),
        "DeleteEphemeris": (
            "delete_ephemeris",
            {"ephemerisId": "00000000-0000-0000-0000-000000000000"},
        ),
        "DeleteMissionProfile": (
            "delete_mission_profile",
            {"missionProfileId": "00000000-0000-0000-0000-000000000000"},
        ),
        # ── Update (fake UUID → NotFoundException → ALLOWED) ────────────────
        "UpdateMissionProfile": (
            "update_mission_profile",
            {"missionProfileId": "00000000-0000-0000-0000-000000000000"},
        ),
        "UpdateEphemeris": (
            "update_ephemeris",
            {"ephemerisId": "00000000-0000-0000-0000-000000000000", "name": "perm-test"},
        ),
    },

    # Elastic Beanstalk
    # Excluded: Create*/Update*/Delete*/Terminate* (create or destroy real environments/apps),
    # SwapEnvironmentCNAMEs/RebuildEnvironment/RestartAppServer (disrupt live workloads).
    "elasticbeanstalk": {
        # ── No required params ───────────────────────────────────────────────
        "DescribeApplications": ("describe_applications", {}),
        "DescribeEnvironments": ("describe_environments", {}),
        "DescribeApplicationVersions": ("describe_application_versions", {}),
        "DescribeAccountAttributes": ("describe_account_attributes", {}),
        "ListAvailableSolutionStacks": ("list_available_solution_stacks", {}),
        "ListPlatformBranches": ("list_platform_branches", {}),
        # ── Fake app/env → NoSuchApplicationException / NoSuchEnvironmentException → ALLOWED ──
        "DescribeConfigurationSettings": (
            "describe_configuration_settings",
            {"ApplicationName": "DOES_NOT_EXIST_APP", "EnvironmentName": "DOES_NOT_EXIST_ENV"},
        ),
        "DescribeEvents": (
            "describe_events",
            {"ApplicationName": "DOES_NOT_EXIST_APP"},
        ),
        "DescribeEnvironmentResources": (
            "describe_environment_resources",
            {"EnvironmentName": "DOES_NOT_EXIST_ENV"},
        ),
        "DescribeEnvironmentHealth": (
            "describe_environment_health",
            {"EnvironmentName": "DOES_NOT_EXIST_ENV", "AttributeNames": ["All"]},
        ),
        "DescribeEnvironmentManagedActions": (
            "describe_environment_managed_actions",
            {"EnvironmentName": "DOES_NOT_EXIST_ENV"},
        ),
        "DescribeEnvironmentManagedActionHistory": (
            "describe_environment_managed_action_history",
            {"EnvironmentName": "DOES_NOT_EXIST_ENV"},
        ),
        "DescribeInstancesHealth": (
            "describe_instances_health",
            {"EnvironmentName": "DOES_NOT_EXIST_ENV", "AttributeNames": ["All"]},
        ),
        "ListTagsForResource": (
            "list_tags_for_resource",
            {"ResourceArn": "arn:aws:elasticbeanstalk:us-east-1:000000000000:application/DOES_NOT_EXIST"},
        ),
    },

    # X-Ray (distributed tracing — service graph is high-value recon)
    # Excluded: put_encryption_config (changes account-wide encryption), put_trace_segments/
    # put_telemetry_records (write trace data), create_* (may create if perms exist),
    # update_* (modifies live resources).
    "xray": {
        # ── No-param reads ───────────────────────────────────────────────────
        "GetEncryptionConfig": ("get_encryption_config", {}),
        "GetGroups": ("get_groups", {}),
        "GetIndexingRules": ("get_indexing_rules", {}),
        "GetSamplingRules": ("get_sampling_rules", {}),
        "GetSamplingStatisticSummaries": ("get_sampling_statistic_summaries", {}),
        "GetTraceSegmentDestination": ("get_trace_segment_destination", {}),
        "ListResourcePolicies": ("list_resource_policies", {}),
        # ── Time-window reads (past 1h, returns empty list if allowed) ────────
        # StartTime/EndTime are required; a short past window avoids large responses.
        "GetServiceGraph": (
            "get_service_graph",
            {
                "StartTime": datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
                "EndTime": datetime.datetime(2024, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc),
            },
        ),
        "GetInsightSummaries": (
            "get_insight_summaries",
            {
                "StartTime": datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
                "EndTime": datetime.datetime(2024, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc),
            },
        ),
        "GetTraceSummaries": (
            "get_trace_summaries",
            {
                "StartTime": datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
                "EndTime": datetime.datetime(2024, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc),
            },
        ),
        "GetTimeSeriesServiceStatistics": (
            "get_time_series_service_statistics",
            {
                "StartTime": datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
                "EndTime": datetime.datetime(2024, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc),
            },
        ),
        # ── Fake-ID reads (not-found → ALLOWED) ──────────────────────────────
        # X-Ray trace IDs follow the format 1-{8hex}-{24hex}.
        "BatchGetTraces": (
            "batch_get_traces",
            {"TraceIds": ["1-00000000-000000000000000000000000"]},
        ),
        "GetInsight": (
            "get_insight",
            {"InsightId": "00000000-0000-0000-0000-000000000000"},
        ),
        "ListRetrievedTraces": (
            "list_retrieved_traces",
            {"RetrievalToken": "00000000-0000-0000-0000-000000000000"},
        ),
        # ── Delete (fake name → not-found → ALLOWED) ─────────────────────────
        "DeleteGroup": (
            "delete_group",
            {"GroupName": "DOES_NOT_EXIST_GROUP"},
        ),
        "DeleteSamplingRule": (
            "delete_sampling_rule",
            {"RuleName": "DOES_NOT_EXIST_RULE"},
        ),
    },
}


def _normalize_services_arg(services_arg: Optional[str], available_services: List[str]) -> List[str]:
    """
    Parse "ec2,s3,iam" into ["ec2", "s3", "iam"] and validate against provided service list.
    """
    if not services_arg:
        return available_services
    requested = [s.strip().lower() for s in services_arg.split(",") if s.strip()]
    valid: List[str] = []
    for s in requested:
        if s in available_services:
            valid.append(s)
        else:
            console.print(f"[yellow]Service '{s}' not recognized or not supported in this module.[/yellow]")
    if not valid:
        console.print("[red]No valid services selected. Aborting.[/red]")
    return valid


def bruteforce_permissions(
    session_mgr: AWSSessionManager,
    services_arg: Optional[str] = None,
    mode: str = "fast",
):
    """
    Extended IAM permission bruteforce across many services.

    mode:
      - "fast" (default): servizi critici veloci (FAST_ACTIONS)
      - "full": enumerazione completa high priority (FULL_ACTIONS)
      - "low": servizi lower priority per enumerazione estesa (LOW_ACTIONS)

    - Supports service filtering: bruteforce_permissions ec2,s3,iam [mode]
    - Stores results under 'iam_bruteforce' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    mode = mode.lower()
    if mode not in ("fast", "full", "low"):
        console.print("[yellow]Unknown mode, falling back to 'fast'.[/yellow]")
        mode = "fast"

    profile_actions = get_profile_actions(mode)
    available_services = list(profile_actions.keys())

    target_services = _normalize_services_arg(services_arg, available_services)
    if not target_services:
        return

    console.print(
        f"[bold blue]🔍 Bruteforcing permissions ({mode} mode) for services: {', '.join(target_services)}[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    results: List[Dict[str, Any]] = []
    error_stats = ErrorStats()  # Track error statistics

    # Retry configuration for bruteforce calls
    retry_config = RetryConfig(
        max_attempts=2,  # Quick retry for transient errors
        base_delay=0.5,
        max_delay=2.0
    )

    # Calculate total number of actions to test
    total_actions = sum(len(profile_actions.get(service, [])) for service in target_services)

    # Create progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("{task.completed}/{task.total} actions"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Testing {len(target_services)} service(s)...",
            total=total_actions
        )

        for service in target_services:
            actions_for_service = profile_actions.get(service, [])
            if not actions_for_service:
                continue

            client = aws_sess.client(service)

            for action_name in actions_for_service:
                # Update progress description with current action
                progress.update(
                    task,
                    description=f"[cyan]{service}:{action_name}"
                )

                # Scegli il mapping in base al mode
                if mode == "full":
                    service_mapping = FULL_CALL_MAPPING.get(service, {})
                elif mode == "low":
                    service_mapping = LOW_CALL_MAPPING.get(service, {})
                else:
                    service_mapping = FAST_CALL_MAPPING.get(service, {})

                if action_name not in service_mapping:
                    # Action present in the profile but not yet mapped to a boto3 call
                    results.append(
                        {
                            "service": service,
                            "action": action_name,
                            "status": "SKIPPED",
                            "error": "No call mapping defined yet",
                        }
                    )
                    progress.advance(task)
                    continue

                method_name, params = service_mapping[action_name]

                status = "UNKNOWN"
                error_message = ""

                # Wrap the API call with retry logic for transient errors
                @with_retry(retry_config, silent=True)
                def call_api():
                    method = getattr(client, method_name)
                    return method(**params)

                try:
                    call_api()
                    status = "ALLOWED"
                    error_message = ""

                except ParamValidationError as e:
                    # boto3 rejected parameters before the request reached AWS —
                    # we have no information about permissions for this action.
                    status = "SKIPPED"
                    error_message = f"ParamValidation: {str(e)[:150]}"

                except Exception as e:
                    # Use improved error categorization
                    aws_error = categorize_error(e)
                    error_stats.record_error(aws_error)

                    if aws_error.category == ErrorCategory.AUTHORIZATION:
                        # Permission denied
                        status = "DENIED"
                        error_message = aws_error.code

                    elif aws_error.category == ErrorCategory.AUTHENTICATION:
                        # Authentication failed (invalid/expired credentials)
                        status = "SKIPPED"
                        error_message = aws_error.code

                    elif aws_error.category == ErrorCategory.VALIDATION:
                        # Parameter validation error - status indeterminate
                        status = "SKIPPED"
                        error_message = aws_error.code

                    elif aws_error.category == ErrorCategory.THROTTLING:
                        # Rate limiting - we can retry but for bruteforce, mark as skipped
                        status = "SKIPPED"
                        error_message = f"RateLimit: {aws_error.code}"

                    elif aws_error.category == ErrorCategory.NETWORK:
                        # Network error - cannot determine permissions
                        status = "SKIPPED"
                        error_message = f"NetworkError: {aws_error.code}"

                    elif aws_error.category == ErrorCategory.RESOURCE_NOT_FOUND:
                        # Resource not found means permission granted (request reached service)
                        status = "ALLOWED"
                        error_message = aws_error.code

                    else:
                        # Any other AWS error means the request reached the service
                        # and authentication passed → permission is granted
                        status = "ALLOWED"
                        error_message = aws_error.code

                # Append result after try-except (always executed)
                results.append({
                    "service": service,
                    "action": action_name,
                    "status": status,
                    "error": error_message,
                })

                # Update progress bar
                progress.advance(task)

    # Persist in session - MERGE with existing results to avoid overwriting
    existing_results = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_bruteforce", [])

    # Merge results, avoiding duplicates based on (service, action) tuple
    # Use a dict with (service, action) as key to deduplicate
    merged_dict = {}

    # First add existing results
    for r in existing_results:
        key = (r.get("service"), r.get("action"))
        merged_dict[key] = r

    # Then add/update with new results (new results take precedence)
    for r in results:
        key = (r.get("service"), r.get("action"))
        merged_dict[key] = r

    # Convert back to list
    merged_results = list(merged_dict.values())

    session_mgr.save_enumeration_data("iam_bruteforce", merged_results)

    # Display merge info
    num_existing = len(existing_results)
    num_new = len(results)
    num_merged = len(merged_results)
    if num_existing > 0:
        console.print(
            f"[dim]Merged {num_new} new results with {num_existing} existing results. "
            f"Total saved: {num_merged} unique actions.[/dim]"
        )

    # Calculate per-service statistics and collect dangerous permissions
    service_stats: Dict[str, Dict[str, int]] = {}
    dangerous_allowed: List[Dict[str, str]] = []

    for r in results:
        svc = r["service"]
        action = r["action"]
        full_action = f"{svc}:{action}"

        if svc not in service_stats:
            service_stats[svc] = {"total": 0, "allowed": 0, "denied": 0, "skipped": 0, "error": 0}
        service_stats[svc]["total"] += 1

        if r["status"] == "ALLOWED":
            service_stats[svc]["allowed"] += 1
            # Check if this is a dangerous permission
            if is_dangerous_permission(full_action):
                dangerous_allowed.append({
                    "service": svc,
                    "action": action,
                    "full_action": full_action,
                    "error": r.get("error", "")
                })
        elif r["status"] == "DENIED":
            service_stats[svc]["denied"] += 1
        elif r["status"] == "SKIPPED":
            service_stats[svc]["skipped"] += 1
        else:
            service_stats[svc]["error"] += 1

    # Summary table by service
    summary_table = Table(title=f"📊 Service Summary (mode: {mode})")
    summary_table.add_column("Service", style="cyan", no_wrap=True)
    summary_table.add_column("Total APIs", style="white", justify="right")
    summary_table.add_column("Allowed", style="green", justify="right")
    summary_table.add_column("Denied", style="red", justify="right")
    summary_table.add_column("Skipped", style="magenta", justify="right")
    summary_table.add_column("Errors", style="yellow", justify="right")

    for svc in sorted(service_stats.keys()):
        stats = service_stats[svc]
        summary_table.add_row(
            svc,
            str(stats["total"]),
            str(stats["allowed"]),
            str(stats["denied"]),
            str(stats["skipped"]),
            str(stats["error"]),
        )

    console.print(summary_table)
    console.print()

    # Dangerous permissions section
    if dangerous_allowed:
        console.print(f"[bold red]⚠️  DANGEROUS PERMISSIONS FOUND ({len(dangerous_allowed)}):[/bold red]")
        console.print("[dim]These permissions are part of known privilege escalation techniques.[/dim]\n")
        for perm in dangerous_allowed:
            console.print(f"  [red]🔥[/red] {perm['full_action']}")
        console.print()

    # Detailed results table
    table = Table(title=f"📋 Detailed Results (tested: {len(results)} actions)")
    table.add_column("Service", style="cyan")
    table.add_column("Action")
    table.add_column("Status")
    table.add_column("Error", style="dim")

    for r in results:
        if r["status"] == "ALLOWED":
            color = "green"
        elif r["status"].startswith("DENIED"):
            color = "red"
        elif r["status"] == "SKIPPED":
            color = "magenta"
        else:
            color = "yellow"

        # Show error details or N/A
        error_display = r.get("error", "") or "N/A"

        # Check if this is a dangerous permission
        full_action = f"{r['service']}:{r['action']}"
        action_display = r["action"]
        if r["status"] == "ALLOWED" and is_dangerous_permission(full_action):
            action_display = f"🔥 {r['action']} [red](DANGEROUS)[/red]"

        table.add_row(r["service"], action_display, f"[{color}]{r['status']}[/{color}]", error_display)

    console.print(table)
    console.print("[green]Bruteforce results saved under key 'iam_bruteforce' in session data.[/green]")

    # Show error statistics if there were any errors
    if error_stats.errors:
        console.print("\n[bold]Error Statistics:[/bold]")
        error_stats.print_summary()

    console.print(
        "\n[dim]Note: this module uses many read-only actions and can be noisy in CloudTrail; "
        "it is designed for assessment, not stealth.[/dim]"
    )
