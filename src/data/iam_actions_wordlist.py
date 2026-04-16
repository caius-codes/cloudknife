# src/data/iam_actions_wordlist.py

from typing import Dict, List


# "fast" profile: actions already used by the current iam_bruteforce module.
# NOTE: we only map the IAM action name here (not the boto3 call parameters),
# because the iam_bruteforce module handles the action -> method/params mapping.
FAST_ACTIONS: Dict[str, List[str]] = {
    "iam": [
        "ListUsers",
        "ListRoles",
        "ListGroups",
        "ListPolicies",
        "GetUser",
        "GetAccountSummary",
        "ListRolePolicies",
        "ListAttachedUserPolicies",
        "ListAttachedRolePolicies",
        "ListAccessKeys",
        "CreateAccessKey",
        "DeleteAccessKey",
        # Top priority additions from aws-enumerator
        "GetAccountAuthorizationDetails",
        "GetCredentialReport",
        "GetAccountPasswordPolicy",
        "ListInstanceProfiles",
        "ListMFADevices",
        "ListVirtualMFADevices",
        "ListAccountAliases",
    ],
    "sts": [
        "GetCallerIdentity",
        "GetSessionToken",
    ],
    "s3": [
        "ListBuckets",
        "ListMultipartUploads",
    ],
    "ec2": [
        "DescribeInstances",
        "DescribeRegions",
        "DescribeVpcs",
        "DescribeSecurityGroups",
        "DescribeSubnets",
        "DescribeVolumes",
        "DescribeNetworkInterfaces",
    ],
    "cloudtrail": [
        "DescribeTrails",
        "GetEventSelectors",
    ],
    "logs": [
        "DescribeLogGroups",
        "DescribeLogStreams",
    ],
    "config": [
        "DescribeConfigurationRecorders",
        "DescribeConfigurationRecorderStatus",
    ],
    "lambda": [
        "ListFunctions",
        "ListEventSourceMappings",
    ],
    "rds": [
        "DescribeDBInstances",
        "DescribeDBClusters",
    ],
    "secretsmanager": [
        "ListSecrets",
        "DescribeSecret",
    ],
    "kms": [
        "ListKeys",
        "DescribeKey",
    ],
    "organizations": [
        "DescribeOrganization",
        "ListAccounts",
    ],
}


FULL_ACTIONS: Dict[str, List[str]] = {
    # IAM - Complete enumeration set from aws-enumerator
    "iam": [
        "ListUsers",
        "ListRoles",
        "ListGroups",
        "ListPolicies",
        "GetUser",
        "GetAccountSummary",
        "ListRolePolicies",
        "ListAttachedUserPolicies",
        "ListAttachedRolePolicies",
        "ListAccessKeys",
        "CreateAccessKey",
        "DeleteAccessKey",
        # Complete IAM enumeration from aws-enumerator
        "GetAccountAuthorizationDetails",
        "GetCredentialReport",
        "GetAccountPasswordPolicy",
        "ListInstanceProfiles",
        "ListMFADevices",
        "ListVirtualMFADevices",
        "ListAccountAliases",
        "ListOpenIDConnectProviders",
        "ListSAMLProviders",
        "ListServerCertificates",
        "ListServiceSpecificCredentials",
        "ListSSHPublicKeys",
        "ListSigningCertificates",
    ],
    "sts": [
        "GetCallerIdentity",
        "GetSessionToken",
    ],

    # S3
    "s3": [
        "ListBuckets",              # list_buckets
        "ListMultipartUploads",     # list_multipart_uploads
        # da aws-enumerator (ulteriori call potrebbero esserci, ma nel file allegato
        # la parte S3 non è nel frammento che ho visto)
    ],

    # EC2 (dal blocco ec2_svc in paste.txt + nostre azioni fast + aws-enumerator additions)
    "ec2": [
        "DescribeAccountAttributes",
        "DescribeInstances",
        "DescribeRegions",
        "DescribeAvailabilityZones",
        "DescribeVpcs",
        "DescribeSubnets",
        "DescribeSecurityGroups",
        "DescribeVolumes",
        "DescribeSnapshots",
        "DescribeNetworkInterfaces",
        "DescribeAddresses",
        "DescribeInstanceAttribute",
        "DescribeInternetGateways",
        "DescribeNatGateways",
        "DescribeRouteTables",
        "DescribeVpcEndpoints",
        "DescribeVpcEndpointServices",
        "DescribeFlowLogs",
        "DescribeNetworkAcls",
        "DescribePlacementGroups",
        "DescribeImages",
        "DescribeKeyPairs",
        "DescribeVpnGateways",
        "DescribeVpnConnections",
        "DescribeCustomerGateways",
        # Additions from aws-enumerator
        "DescribeIamInstanceProfileAssociations",
        "DescribeLaunchTemplates",
        "DescribeTags",
    ],

    "ecs": [
        "ListServices",
        "DescribeClusters",
        "ListClusters",
        "ListTasks",
        "ListTaskDefinitions",
        "ListContainerInstances",
        "ListAccountSettings",
        "ListTaskDefinitionFamilies",
    ],

    # CloudTrail (dal blocco cloudtrail_svc)
    "cloudtrail": [
        "DescribeTrails",
        "GetTrailStatus",
        "GetEventSelectors",
        "ListTrails",
    ],

    # CloudWatch Logs (logs_svc)
    "logs": [
        "DescribeLogGroups",
        "DescribeLogStreams",
        "FilterLogEvents",
        "DescribeMetricFilters",
    ],

    # Config (config_svc)
    "config": [
        "DescribeConfigurationRecorders",
        "DescribeConfigurationRecorderStatus",
        "DescribeConfigurationAggregatorSourcesStatus",
        "DescribeOrganizationConfigRules",
        "DescribeDeliveryChannels",
    ],

    # Lambda (lambda_svc)
    "lambda": [
        "ListFunctions",
        "GetAccountSettings",
        "ListEventSourceMappings",
        "ListAliases",
        "ListLayers",
        "ListLayerVersions",
        "ListProvisionedConcurrencyConfigs",
        "ListFunctionEventInvokeConfigs",
    ],

    # RDS (rds_svc)
    "rds": [
        "DescribeDBInstances",
        "DescribeDBClusters",
        "DescribeDBSubnetGroups",
        "DescribeDBSecurityGroups",
        "DescribeDBParameterGroups",
        "DescribeEvents",
        "DescribePendingMaintenanceActions",
        "DescribeDBClusterSnapshots",
        "DescribeDBSnapshots",
    ],

    # Secrets Manager (secretsmanager_svc)
    "secretsmanager": [
        "ListSecrets",
        "DescribeSecret",
        "GetRandomPassword",
        # optional: "GetSecretValue", if you want the full profile to also test read access
    ],

    # KMS (kms_svc)
    "kms": [
        "ListKeys",
        "DescribeKey",
        "ListAliases",
        "ListGrants",
        "ListKeyPolicies",
    ],

    # Organizations (organizations_svc)
    "organizations": [
        "DescribeOrganization",
        "ListAccounts",
        "ListRoots",
        "ListPolicies",
        "ListPoliciesForTarget",
        "ListTargetsForPolicy",
    ],

    # DynamoDB (nuovo blocco per full)
    "dynamodb": [
        "ListTables",        # enum tabelle
        "DescribeTable",     # metadata (chiavi, PITR, SSE, streams)
        "Scan",              # lettura grezza, utile per vedere se possiamo esfiltrare
        "Query",             # lettura mirata con chiave di partizionamento
        "GetItem",
        "BatchGetItem",
        # Additions from aws-enumerator
        "ListBackups",
        "ListGlobalTables",
    ],

    # ECR (Elastic Container Registry) - from aws-enumerator
    "ecr": [
        "DescribeRepositories",
        "ListImages",
        "GetAuthorizationToken",
        "DescribeImages",
    ],

    # EKS (Kubernetes) - from aws-enumerator
    "eks": [
        "ListClusters",
        "DescribeCluster",
        "ListNodegroups",
        "DescribeNodegroup",
    ],

    # SNS (Simple Notification Service) - from aws-enumerator
    "sns": [
        "ListTopics",
        "ListSubscriptions",
        "GetTopicAttributes",
        "ListTagsForResource",
    ],

    # SQS (Simple Queue Service) - from aws-enumerator
    "sqs": [
        "ListQueues",
        "GetQueueAttributes",
        "ListQueueTags",
    ],

    # CloudFormation - from aws-enumerator
    "cloudformation": [
        "ListStacks",
        "DescribeStacks",
        "ListStackResources",
        "DescribeStackResources",
    ],

    # GuardDuty - from aws-enumerator
    "guardduty": [
        "ListDetectors",
        "GetDetector",
        "ListFindings",
        "GetFindings",
    ],

    # Security Hub - from aws-enumerator
    "securityhub": [
        "DescribeHub",
        "GetFindings",
        "ListEnabledProductsForImport",
    ],

    # SSM (Systems Manager) - from aws-enumerator
    "ssm": [
        "DescribeInstanceInformation",
        "ListCommands",
        "GetParameter",
        "DescribeParameters",
        "ListDocuments",
    ],
}


# "low" profile: lower priority services for extended enumeration
# These services are less critical for pentesting but useful for full enumeration
LOW_ACTIONS: Dict[str, List[str]] = {
    # API Gateway
    "apigateway": [
        "GetRestApis",
        "GetResources",
        "GetStages",
        "GetApiKeys",
    ],

    # AppSync (GraphQL)
    "appsync": [
        "ListGraphqlApis",
        "ListApiKeys",
        "ListDataSources",
    ],

    # EventBridge
    "events": [
        "ListRules",
        "ListEventBuses",
        "ListTargetsByRule",
    ],

    # Athena
    "athena": [
        "ListWorkGroups",
        "ListDataCatalogs",
        "ListQueryExecutions",
    ],

    # Glue (ETL)
    "glue": [
        "GetDatabases",
        "GetTables",
        "GetCrawlers",
        "ListJobs",
    ],

    # Redshift
    "redshift": [
        "DescribeClusters",
        "DescribeClusterSnapshots",
        "DescribeClusterParameterGroups",
    ],

    # Kinesis
    "kinesis": [
        "ListStreams",
        "DescribeStream",
        "ListStreamConsumers",
    ],

    # Route53
    "route53": [
        # List (no required params)
        "ListHostedZones",
        "ListHealthChecks",
        "ListGeoLocations",
        "ListReusableDelegationSets",
        "ListQueryLoggingConfigs",
        "ListTrafficPolicies",
        "ListTrafficPolicyInstances",
        "ListCidrCollections",
        # Get (no required params)
        "GetCheckerIpRanges",
        "GetHealthCheckCount",
        "GetHostedZoneCount",
        "GetTrafficPolicyInstanceCount",
        "GetAccountLimit",
        # Get / List (fake zone/check ID → NoSuchHostedZone → ALLOWED)
        "GetHostedZone",
        "GetDNSSEC",
        "GetHealthCheck",
        "ListResourceRecordSets",
        "ListVpcAssociationAuthorizations",
    ],

    # ELB (Classic & Application/Network)
    "elb": [
        "DescribeLoadBalancers",
        "DescribeTags",
        "DescribeTargetGroups",
    ],

    "elbv2": [
        "DescribeLoadBalancers",
        "DescribeTargetGroups",
        "DescribeListeners",
        "DescribeTags",
    ],

    # EFS (Elastic File System)
    "efs": [
        "DescribeFileSystems",
        "DescribeMountTargets",
        "DescribeAccessPoints",
    ],

    # Glacier
    "glacier": [
        "ListVaults",
        "DescribeVault",
    ],

    # Storage Gateway
    "storagegateway": [
        "ListGateways",
        "DescribeGatewayInformation",
        "ListVolumes",
    ],

    # Batch
    "batch": [
        "DescribeComputeEnvironments",
        "DescribeJobQueues",
        "DescribeJobDefinitions",
    ],

    # Lightsail
    "lightsail": [
        "GetInstances",
        "GetDomains",
        "GetLoadBalancers",
    ],

    # OpenSearch (formerly Elasticsearch)
    "opensearch": [
        "ListDomainNames",
        "DescribeDomain",
    ],

    # Cognito
    "cognito-idp": [
        "ListUserPools",
        "ListIdentityPools",
        "ListUsers",
    ],

    # CloudWatch (metrics & alarms)
    "cloudwatch": [
        "ListMetrics",
        "DescribeAlarms",
        "DescribeAlarmsForMetric",
    ],

    # ACM (Certificate Manager)
    "acm": [
        "ListCertificates",
        "DescribeCertificate",
    ],

    # WAF & WAFv2
    "waf": [
        "ListWebACLs",
        "ListRules",
    ],

    "wafv2": [
        "ListWebACLs",
        "ListRuleGroups",
        "ListIPSets",
    ],

    # X-Ray (distributed tracing — service graph is high-value recon)
    # Excluded: put_encryption_config, put_trace_segments, put_telemetry_records (writes),
    # create_group/create_sampling_rule (may create if perms exist), update_* (live resource changes).
    "xray": [
        # No-param reads
        "GetEncryptionConfig",
        "GetGroups",
        "GetIndexingRules",
        "GetSamplingRules",
        "GetSamplingStatisticSummaries",
        "GetTraceSegmentDestination",
        "ListResourcePolicies",
        # Time-window reads (past 1h window, returns empty list if allowed)
        "GetServiceGraph",
        "GetInsightSummaries",
        "GetTraceSummaries",
        "GetTimeSeriesServiceStatistics",
        # Fake-ID reads (not-found → ALLOWED)
        "BatchGetTraces",
        "GetInsight",
        "ListRetrievedTraces",
        # Delete (fake name → not-found → ALLOWED)
        "DeleteGroup",
        "DeleteSamplingRule",
    ],

    # Elastic Beanstalk
    # Excluded: Create*/Update*/Delete*/Terminate* (create or destroy real environments/apps),
    # SwapEnvironmentCNAMEs/RebuildEnvironment/RestartAppServer (disrupt live workloads).
    "elasticbeanstalk": [
        # No required params
        "DescribeApplications",
        "DescribeEnvironments",
        "DescribeApplicationVersions",
        "DescribeAccountAttributes",
        "ListAvailableSolutionStacks",
        "ListPlatformBranches",
        # Fake app/env → NoSuchApplicationException / NoSuchEnvironmentException → ALLOWED
        "DescribeConfigurationSettings",
        "DescribeEvents",
        "DescribeEnvironmentResources",
        "DescribeEnvironmentHealth",
        "DescribeEnvironmentManagedActions",
        "DescribeEnvironmentManagedActionHistory",
        "DescribeInstancesHealth",
        "ListTagsForResource",
    ],

    # Ground Station (satellite communication — niche, regional service)
    # Excluded: CreateConfig/CreateDataflowEndpointGroup/CreateMissionProfile (would create real
    # resources if permission exists), ReserveContact (would schedule a real satellite contact).
    "groundstation": [
        # List
        "ListConfigs",
        "ListGroundStations",
        "ListMissionProfiles",
        "ListSatellites",
        "ListDataflowEndpointGroups",
        "ListContacts",
        "ListEphemerides",
        "ListTagsForResource",
        # Get
        "GetMinuteUsage",
        "GetConfig",
        "GetDataflowEndpointGroup",
        "GetMissionProfile",
        "GetSatellite",
        "GetAgentConfiguration",
        # Describe
        "DescribeContact",
        "DescribeEphemeris",
        # Delete / Cancel (fake UUID → NotFoundException)
        "CancelContact",
        "DeleteConfig",
        "DeleteDataflowEndpointGroup",
        "DeleteEphemeris",
        "DeleteMissionProfile",
        # Update (fake UUID → NotFoundException)
        "UpdateMissionProfile",
        "UpdateEphemeris",
    ],
}


def get_profile_actions(mode: str) -> Dict[str, List[str]]:
    """
    Restituisce il profilo di azioni in base al mode:
      - "fast": azioni FAST_ACTIONS (servizi critici veloci)
      - "full": FULL_ACTIONS (enumerazione completa high priority)
      - "low": LOW_ACTIONS (servizi lower priority per enumerazione estesa)
    """
    mode = mode.lower()
    if mode == "full":
        return FULL_ACTIONS
    elif mode == "low":
        return LOW_ACTIONS
    return FAST_ACTIONS
