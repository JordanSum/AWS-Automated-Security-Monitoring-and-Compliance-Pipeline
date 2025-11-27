terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.4.0"
    }
  }
}
provider "aws" {
  region = "us-west-2"
}

# Lambda role for automated security response
resource "aws_iam_role" "security_lambda_role" {
  name = "security-automation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Policy for security remediation actions
resource "aws_iam_policy" "security_lambda_policy" {
  name        = "security-automation-policy"
  description = "Allows Lambda to remediate security findings"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BasicLambdaExecution"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "SecurityHubAccess"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2SecurityRemediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:ModifyInstanceAttribute"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-west-2"
          }
        }
      },
      {
        Sid    = "S3BucketRemediation"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketEncryption"
        ]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_lambda_attach" {
  role       = aws_iam_role.security_lambda_role.name
  policy_arn = aws_iam_policy.security_lambda_policy.arn
}

# EC2 Role - Can only access specific S3 buckets and write logs
resource "aws_iam_role" "web_tier_role" {
  name = "web-tier-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Environment = "production"
    Tier        = "web"
    Compliance  = "CIS-Benchmark"
  }
}

# Custom policy - least privilege for EC2 to access S3 and CloudWatch
resource "aws_iam_policy" "web_tier_policy" {
  name        = "web-tier-least-privilege"
  description = "Minimal permissions for web tier EC2 instances"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ReadSpecificBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.aws_s3_bucket_static_assets_arn,
          "${var.aws_s3_bucket_static_assets_arn}/*"
        ]
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/ec2/web-tier/*"
      },
      {
        Sid    = "AllowSecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.web_config.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "web_tier_attach" {
  role       = aws_iam_role.web_tier_role.name
  policy_arn = aws_iam_policy.web_tier_policy.arn
}

# Instance profile for attaching role to EC2
resource "aws_iam_instance_profile" "web_tier_profile" {
  name = "web-tier-instance-profile"
  role = aws_iam_role.web_tier_role.name
}

# Security Engineer Role
resource "aws_iam_role" "security_engineer_role" {
  name = "security-engineer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "security-team-2024"
        }
      }
    }]
  })

  max_session_duration = 3600 # 1 hour sessions
}

resource "aws_iam_policy" "security_engineer_policy" {
  name = "security-engineer-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityServicesFullAccess"
        Effect = "Allow"
        Action = [
          "guardduty:*",
          "securityhub:*",
          "config:*",
          "cloudtrail:*",
          "kms:Describe*",
          "kms:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadOnlyAccessAllServices"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:List*",
          "s3:Get*",
          "iam:Get*",
          "iam:List*",
          "lambda:List*",
          "lambda:Get*"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyIAMModification"
        Effect   = "Deny"
        Action   = [
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Update*",
          "iam:Attach*",
          "iam:Detach*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_engineer_attach" {
  role       = aws_iam_role.security_engineer_role.name
  policy_arn = aws_iam_policy.security_engineer_policy.arn
}

# Read-Only Auditor Role
resource "aws_iam_role" "auditor_role" {
  name = "compliance-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role_policy_attachment" "auditor_attach" {
  role       = aws_iam_role.auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_secretsmanager_secret" "web_config" {
  name = var.secret_name

  tags = {
    Environment = "development"
    Tier        = "web"
  }
}


