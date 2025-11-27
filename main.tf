terraform {
    required_version = ">= 1.0.0"
    required_providers {
      aws = {
        source = "hashicorp/aws"
        version = "~> 6.4.0"
      }
    }
}

provider "aws" {
  region = "us-west-2"
}

module "iam" {
    source = "./modules/iam"
    aws_s3_bucket_static_assets_arn = module.s3.aws_s3_bucket_static_assets_arn
    secret_name = var.secret_name
}

module "s3" {
  source = "./modules/s3"
  bucket_name = var.bucket_name
}