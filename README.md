# AWS Automated Security Monitoring and Compliance Pipeline

[![Terraform](https://img.shields.io/badge/Terraform-v6.4+-purple.svg)](https://www.terraform.io/)
[![AWS Provider](https://img.shields.io/badge/AWS-v6.4.0-orange.svg)](https://registry.terraform.io/providers/hashicorp/aws/latest)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Terraform-based infrastructure-as-code project that deploys a security-focused AWS environment with automated remediation capabilities, least-privilege IAM roles, and CIS Benchmark compliance. Includes Python scripts for IAM security auditing and automated remediation.

## 🏗️ Architecture Overview

![Architecture Diagram](images/Arch.png)

## 📦 Project Structure

```
.
├── main.tf                 # Root module - orchestrates all modules
├── modules/
│   ├── iam/
│   │   ├── main.tf         # IAM roles, policies, and instance profiles
│   │   └── variable.tf     # IAM module variables
│   └── s3/
│       ├── main.tf         # S3 bucket configuration
│       ├── output.tf       # S3 module outputs
│       └── variable.tf     # S3 module variables
├── Python/
│   ├── iam_audit.py        # IAM security auditing script
│   └── iam_remediation.py  # IAM automated remediation script
└── README.md
```

## 🔐 Security Components

### 1. Lambda Security Automation Role
Enables automated remediation of security findings:
- **Security Hub Integration**: Read/update security findings
- **EC2 Remediation**: Remove dangerous security group rules
- **S3 Remediation**: Block public access, enable encryption
- **Region-Locked**: Actions restricted to `us-west-2`

### 2. Web Tier EC2 Role (Least Privilege)
Minimal permissions for web application servers:
- Read-only access to specific S3 bucket
- CloudWatch Logs for application logging
- Secrets Manager access for configuration

### 3. Security Engineer Role
For security team members with:
- Full access to GuardDuty, Security Hub, Config, CloudTrail
- Read-only access to EC2, S3, IAM, Lambda
- **Explicitly denied** IAM modification permissions

### 4. Auditor Role
Read-only compliance auditing:
- AWS managed `SecurityAudit` policy attached
- Perfect for third-party compliance reviews

## 🐍 Python Scripts

### IAM Security Auditor (`Python/iam_audit.py`)
A comprehensive IAM security auditing tool that checks for CIS Benchmark compliance:

| Audit Check | Description | Severity |
|-------------|-------------|----------|
| **Password Policy** | Validates minimum length (14+), complexity requirements, rotation (90 days) | HIGH/CRITICAL |
| **Root Account** | Checks for root access keys and MFA status | CRITICAL |
| **Unused Credentials** | Finds users/keys inactive for 90+ days | MEDIUM |
| **Overly Permissive Policies** | Detects wildcard actions (`*`, `s3:*`, `iam:*`, `ec2:*`) | HIGH |

**Features:**
- Generates JSON reports with timestamps
- Color-coded severity output (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Info)
- Actionable remediation recommendations
- Saves reports to `Reports/` directory

### IAM Remediation Tool (`Python/iam_remediation.py`)
Automated remediation for common IAM security issues:

| Remediation | Description | Safety |
|-------------|-------------|--------|
| **Disable Unused Access Keys** | Deactivates keys unused for 90+ days | Dry-run by default |
| **Enforce MFA Check** | Identifies console users without MFA | Report only |

**Features:**
- **Dry-run mode** (default): Shows what would be changed without making changes
- Safe execution with confirmation prompts
- Detailed logging of all actions

## 🚀 Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 6.4
- [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
- [Python 3.8+](https://www.python.org/downloads/) with pip
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) AWS SDK for Python
- AWS account with appropriate permissions
- (Optional) [AWS Security Hub](https://aws.amazon.com/security-hub/) enabled

### Install Python Dependencies
```bash
pip3 install boto3
```

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd AWS-Automated-Security-Monitoring-and-Compliance-Pipeline
```

### 2. Configure AWS Credentials
```bash
# Option 1: AWS CLI profile
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-west-2"
```

### 3. Customize the S3 Bucket Name
Edit `modules/s3/main.tf` and change the bucket name to something unique:
```hcl
resource "aws_s3_bucket" "static_assets" {
  bucket = "your-unique-bucket-name-123456"  # Must be globally unique
  ...
}
```

### 4. Initialize and Deploy
```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy infrastructure
terraform apply
```

### 5. Verify Deployment
```bash
# List created resources
terraform state list

# Show specific resource details
terraform state show module.iam.aws_iam_role.security_lambda_role
```

## 🧪 Hands-On Testing Scenarios

Follow these step-by-step guides to see the security automation in action.

---

### Scenario 1: Run IAM Security Audit (Python Script)

**Objective**: Audit your AWS account for IAM security issues and generate a compliance report.

#### Step 1: Navigate to the Python Scripts Directory
```bash
cd Python
```

#### Step 2: Create the Reports Directory (If not present!)
```bash
mkdir -p Reports
```

#### Step 3: Run the IAM Audit Script
```bash
python3 iam_audit.py
```

#### Expected Output:
```
🔍 Starting IAM Security Audit...

============================================================
IAM SECURITY AUDIT REPORT
============================================================
Total Checks: 8
🔴 Critical: 1
🟠 High: 2
🟡 Medium: 3
============================================================

🔴 Password Policy: FAIL
   └─ Password length < 14 characters
   └─ Password rotation > 90 days
   💡 Remediation: Update password policy to meet CIS benchmarks

🔴 Root Access Keys: FAIL
   └─ Root account has active access keys
   💡 Remediation: Delete root access keys immediately

🟡 Unused Credentials: FAIL
   └─ User john.doe password unused for 90+ days
   💡 Remediation: Disable or delete user john.doe

📄 Report saved to: Reports/iam_audit_20251126_143022.json
```

#### Step 4: Review the JSON Report
```bash
cat Reports/iam_audit_*.json | python3 -m json.tool
```

---

### Scenario 2: Remediate IAM Issues (Python Script)

**Objective**: Automatically disable unused access keys using the remediation script.

#### Step 1: Run in Dry-Run Mode First (Safe)
```bash
python3 iam_remediation.py
```

#### Expected Output (Dry-Run):
```
🔧 Checking for unused access keys (>90 days)...

⚠️  Key AKIAIOSFODNN7EXAMPLE for user john.doe unused for 120 days
   ℹ️  DRY RUN: Would disable key AKIAIOSFODNN7EXAMPLE

🔧 Checking MFA status for console users...

⚠️  User jane.smith has console access without MFA
   ℹ️  Recommendation: Enforce MFA via IAM policy or disable console access
```

#### Step 2: Run with Remediation Enabled (Caution!)

⚠️ **Warning**: This will make actual changes to your AWS account!

Edit `iam_remediation.py` and change `dry_run=True` to `dry_run=False`:
```python
if __name__ == '__main__':
    # Change dry_run to False to enable actual remediation
    remediator = IAMRemediator(dry_run=False)  # ⚠️ CAUTION!
    remediator.disable_unused_access_keys(90)
    remediator.enforce_mfa_for_console_users()
```

Then run:
```bash
python3 iam_remediation.py
```

#### Expected Output (Live Mode):
```
🔧 Checking for unused access keys (>90 days)...

⚠️  Key AKIAIOSFODNN7EXAMPLE for user john.doe unused for 120 days
   ✅ Disabled key AKIAIOSFODNN7EXAMPLE
```

---

### Scenario 3: Detect and Remediate a Public S3 Bucket (Lambda + EventBridge)

**Objective**: Simulate a security misconfiguration and observe how the automated system can detect and fix it.

---

#### Step 1: Enable AWS Security Hub (if not already enabled)
```bash
aws securityhub enable-security-hub --region us-west-2
```

#### Step 2: Create a "Misconfigured" Test Bucket

**Bash/Linux:**
```bash
# Create a test bucket (use a unique name)
aws s3 mb s3://my-insecure-test-bucket-$(date +%s) --region us-west-2

# Store the bucket name for later
BUCKET_NAME="my-insecure-test-bucket-$(date +%s)"
echo "Bucket name: $BUCKET_NAME"
```

**PowerShell/Windows:**
```powershell
# Create a test bucket (use a unique name)
$timestamp = Get-Date -UFormat %s
aws s3 mb s3://my-insecure-test-bucket-$timestamp --region us-west-2

# Store the bucket name for later
$BUCKET_NAME = "my-insecure-test-bucket-$timestamp"
Write-Host "Bucket name: $BUCKET_NAME"
```

#### Step 3: Intentionally Make the Bucket Public (Misconfiguration)

**Bash/Linux:**
```bash
# Remove public access block (simulating a misconfiguration)
aws s3api delete-public-access-block --bucket $BUCKET_NAME

# Add a public bucket policy
aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::'$BUCKET_NAME'/*"
  }]
}'
```

**PowerShell/Windows:**
```powershell
# Remove public access block (simulating a misconfiguration)
aws s3api delete-public-access-block --bucket $BUCKET_NAME

# Add a public bucket policy
$policy = @"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
  }]
}
"@

aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy $policy
```

#### Step 4: Wait for Security Hub to Detect the Issue
Security Hub typically detects this within 1-24 hours. To check findings:
```bash
aws securityhub get-findings --filters '{
  "ResourceType": [{"Value": "AwsS3Bucket", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' --region us-west-2
```

#### Step 5: Create the Lambda Remediation Function (Provided in Python Folder)
Create a file named `remediate_s3.py`:
```python
import boto3
import json

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    securityhub = boto3.client('securityhub')
    
    # Get bucket name from Security Hub finding
    bucket_name = event['detail']['findings'][0]['Resources'][0]['Id'].split(':')[-1]
    
    print(f"🔒 Remediating public access for bucket: {bucket_name}")
    
    # Block all public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    # Delete the public bucket policy
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
    except Exception as e:
        print(f"No bucket policy to delete: {e}")
    
    print(f"✅ Successfully remediated bucket: {bucket_name}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'Remediated bucket: {bucket_name}')
    }
```

#### Step 6: Deploy the Lambda Function

**Bash/Linux:**
```bash
# Zip the function
zip remediate_s3.zip remediate_s3.py

# Create the Lambda function using the role we created in Terraform IAM module
aws lambda create-function \
  --function-name SecurityRemediationFunction \
  --runtime python3.11 \
  --handler remediate_s3.lambda_handler \
  --role arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/security-automation-lambda-role \
  --zip-file fileb://remediate_s3.zip \
  --region us-west-2
```

**PowerShell/Windows:**
```powershell
# Create zip file using PowerShell
Compress-Archive -Path "remediate_s3.py" -DestinationPath "remediate_s3.zip" -Force

# Create the Lambda function using the role we created in Terraform IAM module
aws lambda create-function `
  --function-name SecurityRemediationFunction `
  --runtime python3.11 `
  --handler remediate_s3.lambda_handler `
  --role "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/security-automation-lambda-role" `
  --zip-file fileb://remediate_s3.zip `
  --region us-west-2
```

#### Step 7: Create EventBridge Rule for Auto-Remediation

**Bash/Linux:**
```bash
# Create rule to trigger Lambda on Security Hub findings
aws events put-rule \
  --name "S3PublicAccessFinding" \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "ResourcesType": ["AwsS3Bucket"]
      }
    }
  }' \
  --region us-west-2

# Add Lambda as target
aws events put-targets \
  --rule "S3PublicAccessFinding" \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-west-2:$(aws sts get-caller-identity --query Account --output text):function:SecurityRemediationFunction" \
  --region us-west-2

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission \
  --function-name SecurityRemediationFunction \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-west-2:$(aws sts get-caller-identity --query Account --output text):rule/S3PublicAccessFinding \
  --region us-west-2
```

**PowerShell/Windows:**
```powershell
# Create rule to trigger Lambda on Security Hub findings
$eventPattern = @'
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
      "ResourcesType": ["AwsS3Bucket"]
    }
  }
}
'@

aws events put-rule `
  --name "S3PublicAccessFinding" `
  --event-pattern $eventPattern `
  --region us-west-2

# Add Lambda as target
aws events put-targets `
  --rule "S3PublicAccessFinding" `
  --targets "Id=1,Arn=arn:aws:lambda:us-west-2:$(aws sts get-caller-identity --query Account --output text):function:SecurityRemediationFunction" `
  --region us-west-2

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission `
  --function-name SecurityRemediationFunction `
  --statement-id EventBridgeInvoke `
  --action lambda:InvokeFunction `
  --principal events.amazonaws.com `
  --source-arn "arn:aws:events:us-west-2:$(aws sts get-caller-identity --query Account --output text):rule/S3PublicAccessFinding" `
  --region us-west-2
```

#### Step 8: Test Manual Invocation

**Bash/Linux:**
```bash
# Manually invoke the Lambda to test
aws lambda invoke \
  --function-name SecurityRemediationFunction \
  --payload '{"detail":{"findings":[{"Resources":[{"Id":"arn:aws:s3:::'$BUCKET_NAME'"}]}]}}' \
  --cli-binary-format raw-in-base64-out \
  response.json \
  --region us-west-2

cat response.json
```

**PowerShell/Windows:**
```powershell
# Manually invoke the Lambda to test
aws lambda invoke `
  --function-name SecurityRemediationFunction `
  --payload '{"detail":{"findings":[{"Resources":[{"Id":"arn:aws:s3:::'$BUCKET_NAME'"}]}]}}' `
  --cli-binary-format raw-in-base64-out `
  response.json `
  --region us-west-2

Get-Content response.json
```

**Note**: There might be a timeout error, if that is encountered, update the function configuration to 30 seconds

**Bash/Linux:**
```bash
# Update timeout
aws lambda update-function-configuration \
  --function-name SecurityRemediationFunction \
  --timeout 30 \
  --region us-west-2
```

**PowerShell/Windows:**
```powershell
# Update timeout
aws lambda update-function-configuration `
  --function-name SecurityRemediationFunction `
  --timeout 30 `
  --region us-west-2
```

#### Step 9: Verify Remediation

**Bash/Linux:**
```bash
# Check that public access is now blocked
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Expected output:
# {
#     "PublicAccessBlockConfiguration": {
#         "BlockPublicAcls": true,
#         "IgnorePublicAcls": true,
#         "BlockPublicPolicy": true,
#         "RestrictPublicBuckets": true
#     }
# }
```

**PowerShell/Windows:**
```powershell
# Check that public access is now blocked
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Expected output:
# {
#     "PublicAccessBlockConfiguration": {
#         "BlockPublicAcls": true,
#         "IgnorePublicAcls": true,
#         "BlockPublicPolicy": true,
#         "RestrictPublicBuckets": true
#     }
# }
```

#### Step 10: Clean Up Test Resources

**Bash/Linux:**
```bash
# Delete the test bucket
aws s3 rb s3://$BUCKET_NAME --force

# Delete the Lambda function (optional)
aws lambda delete-function --function-name SecurityRemediationFunction --region us-west-2

# Delete EventBridge rule (optional)
aws events remove-targets --rule S3PublicAccessFinding --ids 1 --region us-west-2
aws events delete-rule --name S3PublicAccessFinding --region us-west-2
```

**PowerShell/Windows:**
```powershell
# Delete the test bucket
aws s3 rb s3://$BUCKET_NAME --force

# Delete the Lambda function (optional)
aws lambda delete-function --function-name SecurityRemediationFunction --region us-west-2

# Delete EventBridge rule (optional)
aws events remove-targets --rule S3PublicAccessFinding --ids 1 --region us-west-2
aws events delete-rule --name S3PublicAccessFinding --region us-west-2
```

---

## 🧹 Cleanup

To destroy all resources created by this Terraform project:

```bash
terraform destroy
```

**⚠️ Warning**: This will delete all IAM roles, policies, and S3 buckets created by this project.

## 📊 Compliance Mapping

| CIS Benchmark Control | Implementation | Tool |
|----------------------|----------------|------|
| 1.4 - No root access keys | Audited and alerted | `iam_audit.py` |
| 1.5 - MFA enabled | Checked for console users | `iam_audit.py`, `iam_remediation.py` |
| 1.10 - Password policy | Validates all CIS requirements | `iam_audit.py` |
| 1.12 - No unused credentials | Finds keys/passwords unused 90+ days | `iam_audit.py`, `iam_remediation.py` |
| 1.16 - No overly permissive policies | Detects wildcard permissions | `iam_audit.py` |
| 2.1.1 - S3 bucket encryption | Auto-remediated by Lambda | Lambda + EventBridge |
| 2.1.2 - S3 public access | Auto-remediated by Lambda | Lambda + EventBridge |
| 4.1 - Security groups | Monitored and remediable | Lambda IAM Role |

## 🔧 Customization

### Change the AWS Region
Edit `main.tf` and module files:
```hcl
provider "aws" {
  region = "your-preferred-region"
}
```

### Add More Remediation Actions
Extend the Lambda policy in `modules/iam/main.tf`:
```hcl
{
  Sid    = "RDSRemediation"
  Effect = "Allow"
  Action = [
    "rds:ModifyDBInstance"
  ]
  Resource = "*"
}
```

### Restrict to Specific Resources
Use resource ARNs instead of wildcards:
```hcl
Resource = "arn:aws:s3:::my-specific-bucket-*"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project is for educational and demonstration purposes. Before deploying to production:

- Review all IAM policies for your specific security requirements
- Test in a non-production environment first
- Enable AWS CloudTrail for audit logging
- Consider AWS Organizations for multi-account setups
- Regularly review and rotate credentials

## 📚 Additional Resources

- [AWS Security Hub Documentation](https://docs.aws.amazon.com/securityhub/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
