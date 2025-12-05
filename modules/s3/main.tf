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

resource "aws_s3_bucket" "static_assets" {
  bucket = var.bucket_name

  tags = {
    Environment = "development"
    Tier        = "web"
  }
}